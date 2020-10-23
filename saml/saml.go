package saml

import (
	"auth-service/session"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
	"net/http"
	"net/url"
)

func New(opts samlsp.Options) (*samlsp.Middleware, error) {
	// for backwards compatibility, support Logger
	onError := samlsp.DefaultOnError
	// for backwards compatibility, support IDPMetadataURL
	if opts.IDPMetadataURL != nil && opts.IDPMetadata == nil {
		httpClient := opts.HTTPClient
		if httpClient == nil {
			httpClient = http.DefaultClient
		}
		metadata, err := samlsp.FetchMetadata(context.TODO(), httpClient, *opts.IDPMetadataURL)
		if err != nil {
			return nil, err
		}
		opts.IDPMetadata = metadata
	}

	m := &samlsp.Middleware{
		ServiceProvider: DefaultServiceProvider(opts),
		Binding:         "",
		OnError:         onError,
		Session:         session.DefaultSessionProvider(&opts.URL, opts.Key),
	}
	m.RequestTracker = samlsp.DefaultRequestTracker(opts, &m.ServiceProvider)

	return m, nil
}

func NewSaml(idpMetadataURL *url.URL, rootURL *url.URL, keyPair tls.Certificate) *samlsp.Middleware {

	opts := samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataURL,
		SignRequest:    true,
	}

	samlSP, err := New(opts)
	if err != nil {
		panic(err) // TODO handle error
	}
	/*samlSP.Session = session.DefaultSessionProvider(rootURL, keyPair.PrivateKey.(*rsa.PrivateKey))
	samlSP.ServiceProvider =DefaultServiceProvider(opts)
	samlSP.RequestTracker =  samlsp.DefaultRequestTracker(opts, &samlSP.ServiceProvider)*/
	return samlSP
}

func DefaultServiceProvider(opts samlsp.Options) saml.ServiceProvider {
	metadataURL := opts.URL.ResolveReference(&url.URL{Path: "auth/saml/metadata"})
	acsURL := opts.URL.ResolveReference(&url.URL{Path: "auth/saml/acs"})
	sloURL := opts.URL.ResolveReference(&url.URL{Path: "auth/saml/slo"})

	var forceAuthn *bool
	if opts.ForceAuthn {
		forceAuthn = &opts.ForceAuthn
	}
	signatureMethod := dsig.RSASHA1SignatureMethod
	if !opts.SignRequest {
		signatureMethod = ""
	}

	return saml.ServiceProvider{
		EntityID:          opts.EntityID,
		Key:               opts.Key,
		Certificate:       opts.Certificate,
		Intermediates:     opts.Intermediates,
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		SloURL:            *sloURL,
		IDPMetadata:       opts.IDPMetadata,
		ForceAuthn:        forceAuthn,
		SignatureMethod:   signatureMethod,
		AllowIDPInitiated: opts.AllowIDPInitiated,
	}
}
