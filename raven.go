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

type RavenIdentity struct {
	crsID string
}

type user struct {
	crsID        string
	lastVerified time.Time
	uniqueCookie []byte
}

type authenticator struct {
	key   *rsa.PublicKey
	users map[string]user
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

func (auth *authenticator) isAuthorised(r *http.Request) (RavenIdentity, error) {
	crsID, err := r.Cookie("crsID")
	if err != nil {
		return RavenIdentity{}, fmt.Errorf("no crsid")
	}
	uniqueCookie, err := r.Cookie("authIdentity")
	if err != nil {
		return RavenIdentity{}, fmt.Errorf("no authIdentity found")
	}
	uniqueBytes, err := base64.StdEncoding.DecodeString(uniqueCookie.Value)
	if err != nil {
		return RavenIdentity{}, fmt.Errorf("invalid base64 encoding")
	}
	if user, ok := auth.users[crsID.Value]; ok {
		//Random bytes are equal
		if bytes.Equal(user.uniqueCookie, uniqueBytes) {
			return RavenIdentity{crsID.Value}, nil
		}
	}
	return RavenIdentity{}, fmt.Errorf("failed authenticity check")
}

func (auth *authenticator) getRavenInfo(r *http.Request) (RavenIdentity, error) {
	values := r.URL.Query()
	val, ok := values["WLS-Response"]
	if !ok {
		return RavenIdentity{}, fmt.Errorf("WLS-Response not found")
	}
	parts := strings.Split(val[0], "!")
	if len(parts) != 14 {
		return RavenIdentity{}, fmt.Errorf("Invalid length")
	}
	url := strings.Join(parts[:11], "!") + "!"
	if !verifyViaRSA(auth.key, url, parts[13]) {
		return RavenIdentity{}, fmt.Errorf("Failed RSA check")
	}
	return RavenIdentity{parts[6]}, nil
}

func (auth *authenticator) setAuthenticationCookie(identity RavenIdentity, w http.ResponseWriter, r *http.Request) {
	//64 byte random number
	uniqueCookie := make([]byte, 64)
	rand.Read(uniqueCookie)

	auth.users[identity.crsID] = user{
		crsID:        identity.crsID,
		lastVerified: time.Now(),
		uniqueCookie: uniqueCookie,
	}

	expiration := time.Now().Add(2 * 24 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:    "crsID",
		Value:   identity.crsID,
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
		identity, err := auth.getRavenInfo(r)
		if err != nil {
			//Permission denied
			return
		}
		auth.setAuthenticationCookie(identity, w, r)
		//Permission granted
	})
}

func (auth *authenticator) AuthoriseAndHandle(url string, handler func(RavenIdentity, http.ResponseWriter, *http.Request), failed func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
		if identity, err := auth.isAuthorised(r); err != nil {
			handler(identity, w, r)
			return
		}
		failed(w, r)
	})
}

func NewAuthenticator() authenticator {
	key, err := getRSAKey("keys/pubkey2")
	if err != nil {
		panic("Error reading RSA key!")
	}
	return authenticator{
		key,
		make(map[string]user),
	}
}
