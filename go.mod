module auth-service

go 1.13

replace github.com/crewjam/saml => github.com/kleash/saml v0.4.2

require (
	github.com/crewjam/saml v0.0.0-00010101000000-000000000000
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/samitpal/simple-sso v0.0.0-20160815112803-72eb3da9990a
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
)
