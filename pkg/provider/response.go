package provider

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/tzrd/saml/pkg/provider/xml"
	"github.com/tzrd/saml/pkg/provider/xml/saml2"
	"github.com/tzrd/saml/pkg/provider/xml/saml2p"
)

const (
	DefaultTimeFormat                = "2006-01-02T15:04:05.999999Z"
	StatusCodeSuccess                = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusCodeVersionMissmatch       = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	StatusCodeAuthNFailed            = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	StatusCodeInvalidAttrNameOrValue = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
	StatusCodeInvalidNameIDPolicy    = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	StatusCodeRequestDenied          = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	StatusCodeRequestUnsupported     = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
	StatusCodeUnsupportedBinding     = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
	StatusCodeResponder              = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusCodePartialLogout          = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
)

type Response struct {
	PostTemplate    *template.Template
	ProtocolBinding string
	RelayState      string
	AcsUrl          string
	Signature       string
	SigAlg          string
	ErrorFunc       func(err error)

	RequestID string
	Issuer    string
	Audience  string
	SendIP    string
}

func (r *Response) doResponse(request *http.Request, w http.ResponseWriter, response string) {
	if r.AcsUrl == "" {
		if err := xml.Write(w, []byte(response)); err != nil {
			r.ErrorFunc(err)
			return
		}
	}

	switch r.ProtocolBinding {
	case PostBinding:
		respData := base64.StdEncoding.EncodeToString([]byte(response))

		data := AuthResponseForm{
			r.RelayState,
			respData,
			r.AcsUrl,
		}

		if err := r.PostTemplate.Execute(w, data); err != nil {
			r.ErrorFunc(err)
			return
		}
	case RedirectBinding:
		respData, err := xml.DeflateAndBase64([]byte(response))
		if err != nil {
			r.ErrorFunc(err)
			return
		}

		http.Redirect(w, request, fmt.Sprintf("%s?%s", r.AcsUrl, buildRedirectQuery(string(respData), r.RelayState, r.SigAlg, r.Signature)), http.StatusFound)
		return
	default:
		//TODO: no binding
	}
}

type AuthResponseForm struct {
	RelayState                  string
	SAMLResponse                string
	AssertionConsumerServiceURL string
}

func (r *Response) sendBackResponse(
	req *http.Request,
	w http.ResponseWriter,
	resp *saml2p.ResponseType,
) {
	respStr, err := xml.Marshal(resp)
	if err != nil {
		r.ErrorFunc(err)
		return
	}

	r.doResponse(req, w, respStr)
}

func (r *Response) makeUnsupportedBindingResponse(
	message string,
) *saml2p.ResponseType {
	now := time.Now().UTC()
	nowStr := now.Format(DefaultTimeFormat)
	return makeResponse(
		NewID(),
		r.RequestID,
		r.AcsUrl,
		nowStr,
		StatusCodeUnsupportedBinding,
		message,
		r.Issuer,
	)
}

func (r *Response) makeResponderFailResponse(
	message string,
) *saml2p.ResponseType {
	now := time.Now().UTC()
	nowStr := now.Format(DefaultTimeFormat)
	return makeResponse(
		NewID(),
		r.RequestID,
		r.AcsUrl,
		nowStr,
		StatusCodeResponder,
		message,
		r.Issuer,
	)
}

func (r *Response) makeDeniedResponse(
	message string,
) *saml2p.ResponseType {
	now := time.Now().UTC()
	nowStr := now.Format(DefaultTimeFormat)
	return makeResponse(
		NewID(),
		r.RequestID,
		r.AcsUrl,
		nowStr,
		StatusCodeRequestDenied,
		message,
		r.Issuer,
	)
}

func (r *Response) makeFailedResponse(
	message string,
) *saml2p.ResponseType {
	now := time.Now().UTC()
	nowStr := now.Format(DefaultTimeFormat)
	return makeResponse(
		NewID(),
		r.RequestID,
		r.AcsUrl,
		nowStr,
		StatusCodeAuthNFailed,
		message,
		r.Issuer,
	)
}

func (r *Response) makeSuccessfulResponse(
	attributes *Attributes,
) *saml2p.ResponseType {
	now := time.Now().UTC()
	nowStr := "" //now.Format(DefaultTimeFormat)
	fiveFromNowStr := now.Add(5 * time.Minute).Format(DefaultTimeFormat)

	return r.makeAssertionResponse(
		nowStr,
		fiveFromNowStr,
		attributes,
	)
}

func (r *Response) makeAssertionResponse(
	issueInstant string,
	untilInstant string,
	attributes *Attributes,
) *saml2p.ResponseType {

	response := makeResponse(NewID(), r.RequestID, r.AcsUrl, issueInstant, StatusCodeSuccess, "", r.Issuer)
	assertion := makeAssertion(r.RequestID, r.AcsUrl, r.SendIP, issueInstant, untilInstant, r.Issuer, attributes.GetNameID(), attributes.GetSAML(), r.Audience, true)
	response.Assertion = *assertion
	return response
}

func getIssuer(entityID string) *saml2.NameIDType {
	return &saml2.NameIDType{
		Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
		Text:   entityID,
	}
}

func makeAttributeQueryResponse(
	requestID string,
	issuer string,
	entityID string,
	attributes *Attributes,
	queriedAttrs []saml2.AttributeType,
) *saml2p.ResponseType {
	now := time.Now().UTC()
	nowStr := now.Format(DefaultTimeFormat)
	fiveMinutes, _ := time.ParseDuration("5m")
	fiveFromNow := now.Add(fiveMinutes)
	fiveFromNowStr := fiveFromNow.Format(DefaultTimeFormat)

	providedAttrs := []*saml2.AttributeType{}
	attrsSaml := attributes.GetSAML()
	if queriedAttrs == nil || len(queriedAttrs) == 0 {
		for _, attrSaml := range attrsSaml {
			providedAttrs = append(providedAttrs, attrSaml)
		}
	} else {
		for _, attrSaml := range attrsSaml {
			for _, queriedAttr := range queriedAttrs {
				if attrSaml.Name == queriedAttr.Name && attrSaml.NameFormat == queriedAttr.NameFormat {
					providedAttrs = append(providedAttrs, attrSaml)
				}
			}
		}
	}

	response := makeResponse(NewID(), requestID, "", nowStr, StatusCodeSuccess, "", issuer)
	assertion := makeAssertion(requestID, "", "", nowStr, fiveFromNowStr, issuer, attributes.GetNameID(), providedAttrs, entityID, false)
	response.Assertion = *assertion
	return response
}

func makeAssertion(
	requestID string,
	acsURL string,
	sendIP string,
	issueInstant string,
	untilInstant string,
	issuer string,
	nameID *saml2.NameIDType,
	attributes []*saml2.AttributeType,
	audience string,
	authN bool,
) *saml2.AssertionType {
	id := NewID()
	issuerP := getIssuer(issuer)

	ret := &saml2.AssertionType{
		Version:      "2.0",
		Id:           id,
		IssueInstant: issueInstant,
		Issuer:       *issuerP,
		Subject: &saml2.SubjectType{
			NameID: nameID,
			SubjectConfirmation: []saml2.SubjectConfirmationType{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml2.SubjectConfirmationDataType{
						InResponseTo: requestID,
						NotBefore:    issueInstant,
						NotOnOrAfter: untilInstant,
					},
				},
			},
		},
		Conditions: &saml2.ConditionsType{
			NotBefore:    issueInstant,
			NotOnOrAfter: untilInstant,
			AudienceRestriction: []saml2.AudienceRestrictionType{
				{Audience: []string{audience}},
			},
		},
		AttributeStatement: []saml2.AttributeStatementType{
			{Attribute: attributes},
		},
	}
	if acsURL != "" {
		ret.Subject.SubjectConfirmation[0].SubjectConfirmationData.Recipient = acsURL
	}
	if sendIP != "" {
		ret.Subject.SubjectConfirmation[0].SubjectConfirmationData.Address = sendIP
	}
	if authN {
		ret.AuthnStatement = []saml2.AuthnStatementType{
			{
				AuthnInstant: issueInstant,
				SessionIndex: id,
				AuthnContext: saml2.AuthnContextType{
					AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		}
	}
	return ret
}

func makeResponse(
	id string,
	requestID string,
	acsURL string,
	issueInstant string,
	status string,
	message string,
	issuer string,
) *saml2p.ResponseType {
	resp := &saml2p.ResponseType{
		Version:      "2.0",
		Id:           id,
		IssueInstant: issueInstant,
		Status: saml2p.StatusType{
			StatusCode: saml2p.StatusCodeType{
				Value: status,
			},
			StatusMessage: message,
		},
		InResponseTo: requestID,
		Issuer:       getIssuer(issuer),
	}

	if acsURL != "" {
		resp.Destination = acsURL
	}
	return resp
}
