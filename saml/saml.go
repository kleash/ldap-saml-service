package saml

import (
	"auth-service/session"
	"crypto/rsa"
	"crypto/tls"
	"github.com/crewjam/saml/samlsp"
	"net/url"
)

func NewSaml(idpMetadataURL *url.URL, rootURL *url.URL, keyPair tls.Certificate) *samlsp.Middleware {

	opts := samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataURL,
		SignRequest:    true,
	}

	samlSP, err := samlsp.New(opts)
	if err != nil {
		panic(err) // TODO handle error
	}
	samlSP.Session = session.DefaultSessionProvider(rootURL, keyPair.PrivateKey.(*rsa.PrivateKey))
	return samlSP
}
