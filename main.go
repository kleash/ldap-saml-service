package main

import (
	"auth-service/config"
	"auth-service/ldap"
	"auth-service/saml"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/crewjam/saml/samlsp"
	"net/http"
	"net/url"
)

func hello(w http.ResponseWriter, r *http.Request) {
	//TODO change to success json response with user details decoded from jwt
	fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "cn"))
}

func main() {
	keyPair, err := tls.X509KeyPair(config.CERT, config.KEY)
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse(config.IDPMetadataURL())
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse(config.ServerURL())
	if err != nil {
		panic(err) // TODO handle error
	}
	samlSP := saml.NewSaml(idpMetadataURL, rootURL, keyPair)
	ldapProvider, err := ldap.New(rootURL, keyPair.PrivateKey.(*rsa.PrivateKey))
	if err != nil {
		panic(err) // TODO handle error
	}

	app := http.HandlerFunc(hello)
	http.Handle("/loginSaml", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)
	http.Handle("/loginLdap", http.HandlerFunc(ldapProvider.LDAPLogin))

	http.ListenAndServe(fmt.Sprintf(":%s", config.ServerPort()), nil)
}
