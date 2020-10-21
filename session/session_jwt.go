package session

import (
	"auth-service/config"
	"crypto/rsa"
	"fmt"
	"github.com/crewjam/saml/samlsp"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/crewjam/saml"
)

// JWTSessionCodec implements SessionCoded to encode and decode Sessions from
// the corresponding JWT.
type JWTSessionCodec struct {
	SigningMethod jwt.SigningMethod
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           *rsa.PrivateKey
}

var _ samlsp.SessionCodec = JWTSessionCodec{}

func DefaultSessionCodec(rootUrl *url.URL, key *rsa.PrivateKey) JWTSessionCodec {
	return JWTSessionCodec{
		SigningMethod: config.DefaultJWTSigningMethod,
		Audience:      rootUrl.String(),
		Issuer:        rootUrl.String(),
		MaxAge:        config.DefaultSessionMaxAge,
		Key:           key,
	}
}

// New creates a Session from the SAML assertion.
//
// The returned Session is a JWTSessionClaims.
func (c JWTSessionCodec) New(assertion *saml.Assertion) (samlsp.Session, error) {
	attributes := Attributes{
		Username: []string{},
		Name:     []string{},
		Email:    []string{},
		Group:    []string{},
	}
	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attr := range attributeStatement.Attributes {
			if attr.FriendlyName == "mail" || attr.Name == "mail" {
				for _, value := range attr.Values {
					attributes.Email = append(attributes.Email, value.Value)
				}
			} else if attr.FriendlyName == "displayName" || attr.Name == "displayName" {
				for _, value := range attr.Values {
					attributes.Name = append(attributes.Name, value.Value)
				}
			} else if attr.FriendlyName == "role" || attr.Name == "role" {
				for _, value := range attr.Values {
					attributes.Group = append(attributes.Group, value.Value)
				}
			} else if attr.FriendlyName == "uid" || attr.Name == "uid" {
				for _, value := range attr.Values {
					attributes.Username = append(attributes.Username, value.Value)
				}
			}
		}
	}
	return c.NewJWT(attributes)
}

func (c JWTSessionCodec) NewJWT(attr Attributes) (samlsp.Session, error) {
	now := saml.TimeNow()
	claims := JWTSessionClaims{}
	claims.Audience = c.Audience
	claims.Issuer = c.Issuer
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(c.MaxAge).Unix()
	claims.NotBefore = now.Unix()
	claims.Subject = "Authentication"
	claims.Attributes = attr
	return claims, nil
}

// Encode returns a serialized version of the Session.
//
// The provided session must be a JWTSessionClaims, otherwise this
// function will panic.
func (c JWTSessionCodec) Encode(s samlsp.Session) (string, error) {
	claims := s.(JWTSessionClaims) // this will panic if you pass the wrong kind of session

	token := jwt.NewWithClaims(c.SigningMethod, claims)
	signedString, err := token.SignedString(c.Key)
	if err != nil {
		return "", err
	}

	return signedString, nil
}

// Decode parses the serialized session that may have been returned by Encode
// and returns a Session.
func (c JWTSessionCodec) Decode(signed string) (samlsp.Session, error) {
	parser := jwt.Parser{
		ValidMethods: []string{c.SigningMethod.Alg()},
	}
	claims := JWTSessionClaims{}
	_, err := parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
		return c.Key.Public(), nil
	})
	// TODO: check for errors due to bad time and return ErrNoSession
	if err != nil {
		return nil, err
	}
	if !claims.VerifyAudience(c.Audience, true) {
		return nil, fmt.Errorf("expected audience %q, got %q", c.Audience, claims.Audience)
	}
	if !claims.VerifyIssuer(c.Issuer, true) {
		return nil, fmt.Errorf("expected issuer %q, got %q", c.Issuer, claims.Issuer)
	}
	return claims, nil
}

// JWTSessionClaims represents the JWT claims in the encoded session
type JWTSessionClaims struct {
	jwt.StandardClaims
	Attributes Attributes `json:"attr"`
}

var _ samlsp.Session = JWTSessionClaims{}

// GetAttributes implements SessionWithAttributes. It returns the SAMl attributes.
func (c JWTSessionClaims) GetAttributes() Attributes {
	return c.Attributes
}

// Attributes is a map of attributes provided in the SAML assertion
type Attributes struct {
	Username []string `json:"username"`
	Name     []string `json:"name"`
	Email    []string `json:"email"`
	Group    []string `json:"group"`
}
