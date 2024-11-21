package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type user struct {
	Username string
	Password string
}

type tokStruct struct {
	Username string
	Token    string
}

var usersMap map[string]string
var jwtSecKeyword = "secretKey"

// Token revokation list contains token and time it was revoked. As our tokens are short lived,
// this list can be cleared by writing a small service that removed all revoked token that are
// older than 15 minutes (Which is our fixed token expiration time), as they would have anyways expired.
// This will keep our revocation list from growing indefinitely.
var revokeList map[string]time.Time

// Fetch secret keys to environment variable
func loadSecret() {
	// Generally we should keep the key in some vault,
	// to which this service as a client should first authenticate and then fetch the secrets.

	tokenSecret := "iqjKq9in3hQbIO1mctWxMkouIqB3Kcn3"
	if err := os.Setenv(jwtSecKeyword, tokenSecret); err != nil {
		fmt.Println("Error Fetching secret key.")
		panic(err)
	}
}

// Load all existing users to the hash map. Deploying a database would be better to scale the system.
//func loadUsers() {
//}

func encodePass(pass string) string {
	h := sha1.New()
	h.Write([]byte(pass))
	sha := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return sha
}

func main() {
	loadSecret()
	usersMap = make(map[string]string)
	revokeList = make(map[string]time.Time)

	http.HandleFunc("/signup", signUp)
	http.HandleFunc("/signin", signIn)
	http.HandleFunc("/auth", authorizeUser)
	http.HandleFunc("/revoke", tokenRevoke)
	http.HandleFunc("/refresh", tokenRefresh)

	err := http.ListenAndServe(":8484", nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}

}

// 1. User Sign Up
// This function checks the uniqueness of the username and assumes that the
// password sent is strong which the client would have validated before calling the API.
func signUp(w http.ResponseWriter, req *http.Request) {
	// Get username and password from request
	var userPass user
	decoder := json.NewDecoder((req.Body))
	err := decoder.Decode(&userPass)
	if err != nil {
		//io.WriteString(w, err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sha := encodePass(userPass.Password)

	//Check if the username is unique
	_, ok := usersMap[userPass.Username]
	if ok {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, fmt.Sprintf("\nUsername %s exists: Change username to sign in\n", userPass.Username))
		return
	}

	// Add user to our map (using in memory map for simplicity instead of database here)
	usersMap[userPass.Username] = sha

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, fmt.Sprintf("\nSignup successful: User %s Created\n", userPass.Username))

}

// 2. User Sign In
func signIn(w http.ResponseWriter, req *http.Request) {

	// Get username and password from request
	var userPass user
	decoder := json.NewDecoder((req.Body))
	err := decoder.Decode(&userPass)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, err.Error())
		return
	}

	sha := encodePass(userPass.Password)

	//Check if the username exist
	_, ok := usersMap[userPass.Username]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, fmt.Sprintf("\nUsername %s does not exists: Try again\n", userPass.Username))
		return
	}

	// Check password hash with expected password hash
	if usersMap[userPass.Username] != sha {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "\nUnauthorized access, wrong password: Try again\n")
		return
	}

	// Create and return JWT token
	tok, err := createJWTToken(userPass.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, fmt.Sprintf("Internal server Error: %s\n", err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, tok)
}

// 3. Authorize user through token
func authorizeUser(w http.ResponseWriter, req *http.Request) {

	// Get token from request
	var tokenString tokStruct
	decoder := json.NewDecoder((req.Body))
	err := decoder.Decode(&tokenString)
	if err != nil {
		io.WriteString(w, err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Check if the token is valid and not expired
	err = validateJWTToken(tokenString.Token)

	// Check and return proper error in case of unauthorized access
	if err == nil {
		// IF valid check if the token is not in revoked list.
		_, ok := revokeList[tokenString.Token]
		if ok {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "\n Unauthorized access: token revoked \n")
			return
		}

		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "User Authorized")
		return

	} else {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, fmt.Sprintf("\n Unauthorized access: %s \n", err))
	}

	return
}

// 4. Token Revokation
func tokenRevoke(w http.ResponseWriter, req *http.Request) {
	// Get token from request
	var tokenString tokStruct
	decoder := json.NewDecoder((req.Body))
	err := decoder.Decode(&tokenString)
	if err != nil {
		io.WriteString(w, err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Check if the token is valid and not expired
	err = validateJWTToken(tokenString.Token)

	if err == nil {
		// Token is valid
		// Check if token is revoked already.
		_, ok := revokeList[tokenString.Token]
		if ok {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "\n Token revoke failed: Token already revoked \n")
			return
		}

		// Revoke token, add to revocation list
		revokeList[tokenString.Token] = time.Now()

		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "\n Token Revoked \n")
		return
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, fmt.Sprintf("\n Token revoke failed: %s \n", err))
		return
	}
}

// 5. Token Refresh
// Refreshes the token if it is valid signature and not expired
func tokenRefresh(w http.ResponseWriter, req *http.Request) {

	// Get token from request
	var tokenString tokStruct
	decoder := json.NewDecoder((req.Body))
	err := decoder.Decode(&tokenString)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, err.Error())
		return
	}

	//Check if the token is valid and not expired
	err = validateJWTToken(tokenString.Token)

	if err == nil {
		// IF token valid check if the token is not in revoked list.
		_, ok := revokeList[tokenString.Token]
		if ok {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "\n Cannot refresh: token revoked \n")
			return
		}

		// Else create and return JWT token
		tok, err := createJWTToken(tokenString.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, fmt.Sprintf("Internal server Error: %s\n", err.Error()))
			return
		}

		w.WriteHeader(http.StatusOK)
		io.WriteString(w, tok)
		return

	} else {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, fmt.Sprintf("\n Cannot refresh: %s \n", err))
		return
	}
}

// Returns a JWT token which is valid for 15 minutes from now.
func createJWTToken(username string) (string, error) {
	JWTToken := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"iss":      "ankur",
			"exp":      time.Now().Add(time.Minute * 15).Unix(),
		})

	secret := os.Getenv(jwtSecKeyword)
	if secret == "" {
		return "", errors.New("key fetch error")
	}

	tokenString, err := JWTToken.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Validate JWT Token
func validateJWTToken(tokenString string) error {
	secret := os.Getenv(jwtSecKeyword)
	tok, err := jwt.Parse(tokenString, func(tok *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return err
	} else if tok == nil {
		return errors.New("internal server error")
	}
	return nil
}
