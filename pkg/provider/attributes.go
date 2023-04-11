package provider

import (
	"github.com/tzrd/saml/pkg/provider/models"
	"github.com/tzrd/saml/pkg/provider/xml/saml"
	"github.com/tzrd/saml/pkg/provider/xml/saml2"
)

const (
	AttributeEmail int = iota
	AttributeFullName
	AttributeGivenName
	AttributeSurname
	AttributeUsername
	AttributeUserID
)

type Attributes struct {
	email     string
	fullName  string
	givenName string
	surname   string
	userID    string
	username  string
}

var _ models.AttributeSetter = &Attributes{}

func (a *Attributes) GetNameID() *saml2.NameIDType {
	return &saml2.NameIDType{
		Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		Text:   a.username,
	}
}

func (a *Attributes) SetEmail(value string) {
	a.email = value
}

func (a *Attributes) SetFullName(value string) {
	a.fullName = value
}

func (a *Attributes) SetGivenName(value string) {
	a.givenName = value
}

func (a *Attributes) SetSurname(value string) {
	a.surname = value
}

func (a *Attributes) SetUsername(value string) {
	a.username = value
}

func (a *Attributes) SetUserID(value string) {
	a.userID = value
}

func (a *Attributes) GetSAML() []*saml.AttributeType {
	attrs := make([]*saml.AttributeType, 0)
	if a.email != "" {
		attrs = append(attrs, &saml.AttributeType{
			Name:           "Email",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.email},
		})
	}
	if a.surname != "" {
		attrs = append(attrs, &saml.AttributeType{
			Name:           "SurName",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.surname},
		})
	}
	if a.givenName != "" {
		attrs = append(attrs, &saml.AttributeType{
			Name:           "FirstName",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.givenName},
		})
	}
	if a.fullName != "" {
		attrs = append(attrs, &saml.AttributeType{
			Name:           "FullName",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.fullName},
		})
	}
	if a.username != "" {
		attrs = append(attrs, &saml.AttributeType{
			Name:           "UserName",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.username},
		})
	}
	if a.userID != "" {
		attrs = append(attrs, &saml.AttributeType{
			Name:           "UserID",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.userID},
		})
	}
	return attrs
}

func (a *Attributes) GetSAMLV2() []*saml2.AttributeType {
	attrs := make([]*saml2.AttributeType, 0)
	if a.email != "" {
		attrs = append(attrs, &saml2.AttributeType{
			Name:           "Email",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.email},
		})
	}
	if a.surname != "" {
		attrs = append(attrs, &saml2.AttributeType{
			Name:           "SurName",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.surname},
		})
	}
	if a.givenName != "" {
		attrs = append(attrs, &saml2.AttributeType{
			Name:           "FirstName",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.givenName},
		})
	}
	if a.fullName != "" {
		attrs = append(attrs, &saml2.AttributeType{
			Name:           "FullName",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.fullName},
		})
	}
	if a.username != "" {
		attrs = append(attrs, &saml2.AttributeType{
			Name:           "UserName",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.username},
		})
	}
	if a.userID != "" {
		attrs = append(attrs, &saml2.AttributeType{
			Name:           "UserID",
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: []string{a.userID},
		})
	}
	return attrs
}
