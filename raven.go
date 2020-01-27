package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type User struct {
	crsID        string
	lastVerified time.Time
	uniqueCookie []byte
}

type authenticator struct {
	key   *rsa.PublicKey
	users map[string]User
}

func getRSAKey(file string) (*rsa.PublicKey, error) {
	r, _ := ioutil.ReadFile(file)
	block, _ := pem.Decode(r)
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func decodeRavenBase64(text string) ([]byte, error) {
	text = strings.ReplaceAll(text, "-", "+")
	text = strings.ReplaceAll(text, ".", "/")
	text = strings.ReplaceAll(text, "_", "=")
	return base64.StdEncoding.DecodeString(text)
}

func verifyViaRSA(key *rsa.PublicKey, messageStr, signatureStr string) bool {
	signatureData, _ := decodeRavenBase64(signatureStr)
	messageHash := sha1.Sum([]byte(messageStr))
	return rsa.VerifyPKCS1v15(key, crypto.SHA1, messageHash[:], signatureData) == nil
}

func (auth *authenticator) isAuthorised(r *http.Request) bool {
	crsID, err := r.Cookie("crsID")
	if err != nil {
		fmt.Println("crsID not found!")
		return false
	}
	uniqueCookie, err := r.Cookie("authIdentity")
	if err != nil {
		fmt.Println("authIdentity not found!")
		return false
	}
	uniqueBytes, err := base64.StdEncoding.DecodeString(uniqueCookie.Value)
	if err != nil {
		fmt.Println("Invalid base64 encoding!")
		return false
	}
	if user, ok := auth.users[crsID.Value]; ok {
		//Random bytes are equal
		return bytes.Equal(user.uniqueCookie, uniqueBytes)
	}
	return false
}

func (auth *authenticator) getRavenInfo(r *http.Request) (string, error) {
	values := r.URL.Query()
	val, ok := values["WLS-Response"]
	if !ok {
		return "", fmt.Errorf("WLS-Response not found")
	}
	parts := strings.Split(val[0], "!")
	if len(parts) != 14 {
		return "", fmt.Errorf("Invalid length")
	}
	url := strings.Join(parts[:11], "!") + "!"
	if !verifyViaRSA(auth.key, url, parts[13]) {
		return "", fmt.Errorf("Failed RSA check")
	}
	return parts[6], nil
}

func (auth *authenticator) setAuthenticationCookie(crsID string, w http.ResponseWriter, r *http.Request) {
	//64 byte random number
	uniqueCookie := make([]byte, 64)
	rand.Read(uniqueCookie)

	auth.users[crsID] = User{
		crsID:        crsID,
		lastVerified: time.Now(),
		uniqueCookie: uniqueCookie,
	}

	expiration := time.Now().Add(2 * 24 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:    "crsID",
		Value:   crsID,
		Expires: expiration,
		Path:    "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:    "authIdentity",
		Value:   base64.StdEncoding.EncodeToString(uniqueCookie),
		Expires: expiration,
		Path:    "/",
	})
}

func (auth *authenticator) HandleRavenAuthenticator(url string) {
	http.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
		crsID, err := auth.getRavenInfo(r)
		if err != nil {
			//Permission denied
			return
		}
		auth.setAuthenticationCookie(crsID, w, r)
		//Permission granted
	})
}

func (auth *authenticator) AuthoriseAndHandle(url string, handler func(w http.ResponseWriter, r *http.Request)) {
	http.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
		if !auth.isAuthorised(r) {
			fmt.Println("Auth failed!")
			return
		}
		handler(w, r)
	})
}

func NewAuthenticator() authenticator {
	key, err := getRSAKey("keys/pubkey2")
	if err != nil {
		panic("Error reading RSA key!")
	}
	return authenticator{
		key,
		make(map[string]User),
	}
}
