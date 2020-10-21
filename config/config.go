package config

import (
	"github.com/dgrijalva/jwt-go"
	"os"
	"strconv"
	"time"
)

const DefaultSessionCookieName = "token"
const DefaultSessionMaxAge = time.Hour
var DefaultJWTSigningMethod = jwt.SigningMethodRS256

// All environment variables config goes here for better tracking.
var ConfMap = map[string]string{
	"server_url":  "server_url",
	"server_port": "server_port",

	// ldap configs
	"ldap_host":       "ldap_host",
	"ldap_port":       "ldap_port",
	"ldap_ssl":        "ldap_ssl",
	"ldap_basedn":     "ldap_basedn",
	"ldap_binddn":     "ldap_binddn",
	"ldap_bindpasswd": "ldap_bindpasswd",

	//saml config
	"idp_metadata_url": "idp_metadata_url",
}
var (
	KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi
3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E
PsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB
AoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ
CT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS
JEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU
N3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/
fbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU
4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM
Rq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA
yfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr
vBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6
hU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==
-----END RSA PRIVATE KEY-----
`)
	CERT = []byte(`-----BEGIN CERTIFICATE-----
MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJV
UzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0
MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9
ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmH
O8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKv
Rsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgk
akpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeT
QLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvn
OwJlNCASPZRH/JmF8tX0hoHuAQ==
-----END CERTIFICATE-----
`)
)

func IDPMetadataURL() string {
	return setDefaultString(os.Getenv(ConfMap["idp_metadata_url"]), "https://samltest.id/saml/idp")
}
func ServerURL() string {
	return setDefaultString(os.Getenv(ConfMap["server_url"]), "http://localhost:8000")
}
func ServerPort() string {
	return setDefaultString(os.Getenv(ConfMap["server_port"]), "8000")
}
func LdapHost() string { return setDefaultString(os.Getenv(ConfMap["ldap_host"]), "localhost") }
func LdapPort() (int, error) {
	return strconv.Atoi(setDefaultString(os.Getenv(ConfMap["ldap_port"]), "389"))
}
func LdapSsl() (bool, error) {
	return strconv.ParseBool(setDefaultString(os.Getenv(ConfMap["ldap_ssl"]), "true"))
}
func LdapBaseDn() string     { return os.Getenv(ConfMap["ldap_basedn"]) }
func LdapBindDn() string     { return os.Getenv(ConfMap["ldap_binddn"]) }
func LdapBindPasswd() string { return os.Getenv(ConfMap["ldap_bindpasswd"]) }

// setDefaultString returns a given default string.
func setDefaultString(s string, d string) string {
	if s == "" {
		return d
	}
	return s
}
