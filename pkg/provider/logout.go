package provider

import (
	"fmt"
	"net/http"

	"github.com/zitadel/logging"

	"github.com/tzrd/saml/pkg/provider/checker"
	"github.com/tzrd/saml/pkg/provider/serviceprovider"
	"github.com/tzrd/saml/pkg/provider/xml"
	"github.com/tzrd/saml/pkg/provider/xml/samlp"
)

type LogoutRequestForm struct {
	LogoutRequest string
	Encoding      string
	RelayState    string
}

func (p *IdentityProvider) logoutHandleFunc(w http.ResponseWriter, r *http.Request) {
	checkerInstance := checker.Checker{}
	var logoutRequestForm *LogoutRequestForm
	var logoutRequest *samlp.LogoutRequestType
	var err error
	var sp *serviceprovider.ServiceProvider

	response := &LogoutResponse{
		LogoutTemplate: p.logoutTemplate,
		ErrorFunc: func(err error) {
			http.Error(w, fmt.Errorf("failed to send response: %w", err).Error(), http.StatusInternalServerError)
		},
		Issuer: p.GetEntityID(r.Context()),
	}

	// parse from to get logout request
	checkerInstance.WithLogicStep(
		func() error {
			logoutRequestForm, err = getLogoutRequestFromRequest(r)
			if err != nil {
				return err
			}
			response.RelayState = logoutRequestForm.RelayState
			return nil
		},
		func() {
			http.Error(w, fmt.Errorf("failed to parse form: %w", err).Error(), http.StatusInternalServerError)
		},
	)

	//decode logout request to internal struct
	checkerInstance.WithLogicStep(
		func() error {
			logoutRequest, err = xml.DecodeLogoutRequest(logoutRequestForm.Encoding, logoutRequestForm.LogoutRequest)
			if err != nil {
				return err
			}
			response.RelayState = logoutRequestForm.RelayState
			response.RequestID = logoutRequest.Id
			return nil
		},
		func() {
			response.sendBackLogoutResponse(w, response.makeUnsupportedlLogoutResponse(fmt.Errorf("failed to decode request: %w", err).Error()))
		},
	)

	//verify required data in request
	checkerInstance.WithLogicStep(
		checkIfRequestTimeIsStillValid(
			func() string { return logoutRequest.IssueInstant },
			func() string { return logoutRequest.NotOnOrAfter },
		),
		func() {
			response.sendBackLogoutResponse(w, response.makeDeniedLogoutResponse(fmt.Errorf("failed to validate request: %w", err).Error()))
		},
	)

	// get persisted service provider from issuer out of the request
	checkerInstance.WithLogicStep(
		func() error {
			sp, err = p.GetServiceProvider(r.Context(), logoutRequest.Issuer.Text)
			return err
		},
		func() {
			response.sendBackLogoutResponse(w, response.makeDeniedLogoutResponse(fmt.Errorf("failed to find registered serviceprovider: %w", err).Error()))
		},
	)

	// get logoutURL from provided service provider metadata
	checkerInstance.WithValueStep(
		func() {
			if sp.Metadata.SPSSODescriptor.SingleLogoutService != nil {
				for _, url := range sp.Metadata.SPSSODescriptor.SingleLogoutService {
					response.LogoutURL = url.Location
					break
				}
			}
		},
	)

	//check and log errors if necessary
	if checkerInstance.CheckFailed() {
		return
	}

	response.sendBackLogoutResponse(
		w,
		response.makeSuccessfulLogoutResponse(),
	)
	logging.Info(fmt.Sprintf("logout request for user %s", logoutRequest.NameID.Text))
}

func getLogoutRequestFromRequest(r *http.Request) (*LogoutRequestForm, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	request := &LogoutRequestForm{
		LogoutRequest: r.Form.Get("SAMLRequest"),
		Encoding:      r.Form.Get("SAMLEncoding"),
		RelayState:    r.Form.Get("RelayState"),
	}

	return request, nil
}
