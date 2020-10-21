package ldap

import (
	"auth-service/config"
	"errors"
)

type Config struct {
	host       string
	port       int
	ssl        bool
	basedn     string
	binddn     string
	bindPasswd string
}

// ldapConfig sets up ldap config from the env.
func (l *Config) setupLdapConfig() error {

	l.host = config.LdapHost()
	port, err := config.LdapPort()
	if err != nil {
		return err
	}
	l.port = port
	ssl, err := config.LdapSsl()
	if err != nil {
		return err
	}
	l.ssl = ssl
	l.basedn = config.LdapBaseDn()
	l.binddn = config.LdapBindDn()
	l.bindPasswd = config.LdapBindPasswd()
	if l.binddn != "" && l.bindPasswd == "" {
		return errors.New("bind dn is set but bind password is not set")
	}
	return nil
}
