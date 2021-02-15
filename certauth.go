package mutualtls

import (
	"bytes"
	// "crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type AuthHandler interface {
	ValidateOU(ous []string, route string) (matched string, allowed bool)
	ValidateCN(cn, route string) (allowed bool)
}

// Auth is an instance of the middleware
type Auth struct {
	authHandler         AuthHandler
	authErrHandler      http.Handler
	setReqHeaders       bool
	reqHeaderIdentifier string
}

func defaultAuthErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Authentication Failed", http.StatusForbidden)
}

// NewAuth returns an auth
func NewAuth(authHandler AuthHandler) *Auth {
	return &Auth{authHandler: authHandler,
		authErrHandler:      http.HandlerFunc(defaultAuthErrorHandler),
		setReqHeaders:       false,
		reqHeaderIdentifier: "",
	}
}

func (a *Auth) SetAuthErrorHandler(handler http.Handler) {
	a.authErrHandler = handler
}

func (a *Auth) SetReqHeaders(set bool) {
	a.setReqHeaders = set
}

func (a *Auth) SetReqHeaderIdentifier(ident string) {
	a.reqHeaderIdentifier = ident
}

func (a *Auth) RouterHandler(h httprouter.Handle) httprouter.Handle {
	return httprouter.Handle(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Process will return who the user is, or an error meaning it has handled the 401
		who, err := a.Process(w, r, ps.MatchedRoutePath())
		if err != nil {
			return
		}

		// Now we add the auth information to the header
		// This is done by first striping any "X-TLS-Auth" headers
		// and then writing an X-TLS-Auth header containing OU and CN
		// TODO: Should we sign this info?
		if a.setReqHeaders {
			ident := "X-TLS-Auth"
			if a.reqHeaderIdentifier != "" {
				ident = a.reqHeaderIdentifier
			}
			r.Header.Del(ident)
			r.Header.Add(ident, who)
		}
		h(w, r, ps)
	})
}

// Process is the main Entrypoint
func (a *Auth) Process(w http.ResponseWriter, r *http.Request, route string) (string, error) {
	if err := a.ValidateRequest(r); err != nil {
		return "", err
	}

	// Validate OU
	ou, ok := a.authHandler.ValidateOU(r.TLS.VerifiedChains[0][0].Subject.OrganizationalUnit, route)
	if !ok {
		a.authErrHandler.ServeHTTP(w, r)
		return "", fmt.Errorf("Cert failed OU validation for %v", r.TLS.VerifiedChains[0][0].Subject.OrganizationalUnit)
	}

	// Validate CN
	cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
	if !a.authHandler.ValidateCN(cn, route) {
		a.authErrHandler.ServeHTTP(w, r)
		return "", fmt.Errorf("Cert failed CN validation for %s", cn)
	}

	//TODO: Is this what we want to do? OU/CN?
	return ou + "/" + cn, nil
}

// ValidateRequest perfomrs verification on the TLS certs and chain
func (a *Auth) ValidateRequest(r *http.Request) error {
	// ensure we can process this request
	if r.TLS == nil || r.TLS.VerifiedChains == nil {
		return errors.New("No cert chain detected")
	}

	// TODO: Figure out if having multiple validated peer leaf certs is possible. For now, only validate
	// one cert, and make sure it matches the first peer certificate
	if r.TLS.PeerCertificates != nil {
		if !bytes.Equal(r.TLS.PeerCertificates[0].Raw, r.TLS.VerifiedChains[0][0].Raw) {
			return errors.New("First peer certificate not first verified chain leaf")
		}
	}

	return nil
}
