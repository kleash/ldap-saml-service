// package ldap is an sso implementation. It uses an ldap backend to authenticate and optionally
// utilize ldap group memberships for setting up roles in the cookie/jwt which can later be used
// by applications for authorization.
package ldap

import (
	"auth-service/session"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/samitpal/simple-sso/sso"
)

type Provider struct {
	Ldap    *Config
	Session session.CookieSessionProvider
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

var (
	ErrUserNotFound = sso.ErrUserNotFound
	ErrUnauthorized = sso.ErrUnAuthorized
)

func New(rootURL *url.URL, key *rsa.PrivateKey) (*Provider, error) {
	l := new(Config)
	err := l.setupLdapConfig()
	if err != nil {
		return nil, err
	}

	return &Provider{l, session.DefaultSessionProvider(rootURL, key), DefaultOnError}, nil
}

func DefaultOnError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("ERROR: %s", err)
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

func (ls Provider) LDAPLogin(w http.ResponseWriter, r *http.Request) {
	redirectURI := "/"
	r.ParseForm()
	if r.PostFormValue("query_string") != "" {
		redirectURI = r.PostFormValue("query_string")
	}
	attr, err := ls.Auth(r.PostFormValue("username"), r.PostFormValue("password"))
	if err != nil {
		ls.OnError(w, r, err)
		return
	}
	if err := ls.Session.CreateSessionGeneric(w, r, attr); err != nil {
		ls.OnError(w, r, err)
		return
	}
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func (ls Provider) Auth(u string, p string) (*session.Attributes, error) {

	ldap.DefaultTimeout = 30 * time.Second // applies to Dial and DialTLS methods.
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ls.Ldap.host, ls.Ldap.port))
	if err != nil {
		return nil, err
	}
	defer l.Close()

	// Reconnect with TLS if sso_ldap_ssl env is set.
	if ls.Ldap.ssl {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
	}

	// First bind with a read only user
	if ls.Ldap.binddn != "" {
		err = l.Bind(ls.Ldap.binddn, ls.Ldap.bindPasswd)
		if err != nil {
			return nil, err
		}
	}

	// Search for the given username
	searchRequestUser := ldap.NewSearchRequest(
		ls.Ldap.basedn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, // sets a time limit of 30 secs
		fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", u),
		[]string{"dn"},
		nil,
	)

	sru, err := l.Search(searchRequestUser)
	if err != nil {
		return nil, err
	}

	if len(sru.Entries) != 1 {
		return nil, ErrUserNotFound
	}

	userdn := sru.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, p)
	if err != nil {
		return nil, ErrUnauthorized
	}

	// Now find the group membership
	var g []string
	searchRequestGroups := ldap.NewSearchRequest(
		ls.Ldap.basedn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, // sets a time limit of 30 secs
		fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", u),
		[]string{"cn"},
		nil,
	)
	srg, err := l.Search(searchRequestGroups)
	if err != nil {
		return nil, err
	}

	g = srg.Entries[0].GetAttributeValues("cn")

	//TODO fetch name and email
	return &session.Attributes{
		Username: []string{u},
		Name:     nil,
		Email:    nil,
		Group:    g,
	}, nil
}
