package raven

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

// Identity uniquely represents a single raven user
type Identity struct {
	CrsID string
}

// Authenticator contains information required to verify a user's identity
type Authenticator struct {
	key   *rsa.PublicKey
	users map[string]user
}

type user struct {
	crsID        string
	lastVerified time.Time
	uniqueCookie []byte
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

func (auth *Authenticator) isAuthorised(r *http.Request) (Identity, error) {
	crsID, err := r.Cookie("crsID")
	if err != nil {
		return Identity{}, fmt.Errorf("no crsid")
	}
	uniqueCookie, err := r.Cookie("authIdentity")
	if err != nil {
		return Identity{}, fmt.Errorf("no authIdentity found")
	}
	uniqueBytes, err := base64.StdEncoding.DecodeString(uniqueCookie.Value)
	if err != nil {
		return Identity{}, fmt.Errorf("invalid base64 encoding")
	}
	if user, ok := auth.users[crsID.Value]; ok {
		//Random bytes are equal
		if bytes.Equal(user.uniqueCookie, uniqueBytes) {
			return Identity{crsID.Value}, nil
		}
	}
	return Identity{}, fmt.Errorf("failed authenticity check")
}

func (auth *Authenticator) getRavenInfo(r *http.Request) (Identity, error) {
	values := r.URL.Query()
	val, ok := values["WLS-Response"]
	if !ok {
		return Identity{}, fmt.Errorf("WLS-Response not found")
	}
	parts := strings.Split(val[0], "!")
	if len(parts) != 14 {
		return Identity{}, fmt.Errorf("Invalid length")
	}
	url := strings.Join(parts[:11], "!") + "!"
	if !verifyViaRSA(auth.key, url, parts[13]) {
		return Identity{}, fmt.Errorf("Failed RSA check")
	}
	return Identity{parts[6]}, nil
}

func (auth *Authenticator) setAuthenticationCookie(identity Identity, w http.ResponseWriter, r *http.Request) {
	//64 byte random number
	uniqueCookie := make([]byte, 64)
	rand.Read(uniqueCookie)

	auth.users[identity.CrsID] = user{
		crsID:        identity.CrsID,
		lastVerified: time.Now(),
		uniqueCookie: uniqueCookie,
	}

	expiration := time.Now().Add(2 * 24 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:    "crsID",
		Value:   identity.CrsID,
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

// HandleAuthenticationURL listens for and validates raven requests
func (auth *Authenticator) HandleAuthenticationURL(url string, handler func(Identity, http.ResponseWriter, *http.Request), failed func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
		identity, err := auth.getRavenInfo(r)
		if err != nil {
			//Permission denied
			failed(w, r)
			return
		}
		auth.setAuthenticationCookie(identity, w, r)
		handler(identity, w, r)
	})
}

// AuthoriseAndHandle ensures user has valid authentication cookies before handling request
func (auth *Authenticator) AuthoriseAndHandle(url string, handler func(Identity, http.ResponseWriter, *http.Request), failed func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
		if identity, err := auth.isAuthorised(r); err == nil {
			handler(identity, w, r)
			return
		}
		failed(w, r)
	})
}

// NewAuthenticator loads Raven's RSA key from a file and enables authentication
func NewAuthenticator(keyPath string) Authenticator {
	key, err := getRSAKey(keyPath)
	if err != nil {
		panic("Error reading RSA key!")
	}
	return Authenticator{
		key,
		make(map[string]user),
	}
}
