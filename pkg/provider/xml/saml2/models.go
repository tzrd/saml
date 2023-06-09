package saml2

import (
	"encoding/xml"

	"github.com/tzrd/saml/pkg/provider/xml/xenc"
	"github.com/tzrd/saml/pkg/provider/xml/xml2_dsig"
)

type BaseIDAbstractType struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion BaseID"`
	InnerXml string   `xml:",innerxml"`
}

type NameIDType struct {
	XMLName         xml.Name
	Saml2           string `xml:"xmlns:saml2,attr"`
	Format          string `xml:"Format,attr,omitempty"`
	SPProvidedID    string `xml:"SPProvidedID,attr,omitempty"`
	NameQualifier   string `xml:"NameQualifier,attr,omitempty"`
	SPNameQualifier string `xml:"SPNameQualifier,attr,omitempty"`
	Text            string `xml:",chardata"`
	//InnerXml        string `xml:",innerxml"`
}

type EncryptedElementType struct {
	XMLName       xml.Name
	EncryptedData xenc.EncryptedDataType  `xml:"EncryptedData"`
	EncryptedKey  []xenc.EncryptedKeyType `xml:"EncryptedKey"`
	//InnerXml      string                  `xml:",innerxml"`
}

type AssertionType struct {
	XMLName                xml.Name                     `xml:"saml2:Assertion"`
	Saml2                  string                       `xml:"xmlns:saml2,attr"`
	Version                string                       `xml:"Version,attr"`
	Id                     string                       `xml:"ID,attr"`
	IssueInstant           string                       `xml:"IssueInstant,attr"`
	Issuer                 NameIDType                   `xml:"saml2:Issuer"`
	Signature              *xml2_dsig.SignatureType     `xml:"ds:Signature"`
	Subject                *SubjectType                 `xml:"saml2:Subject"`
	Conditions             *ConditionsType              `xml:"saml2:Conditions"`
	Advice                 *AdviceType                  `xml:"saml2:Advice"`
	Statement              []StatementAbstractType      `xml:"saml2:Statement"`
	AuthnStatement         []AuthnStatementType         `xml:"saml2:AuthnStatement"`
	AuthzDecisionStatement []AuthzDecisionStatementType `xml:"saml2:AuthzDecisionStatement"`
	AttributeStatement     []AttributeStatementType     `xml:"saml2:AttributeStatement"`
	//InnerXml               string                       `xml:",innerxml"`
}

type SubjectType struct {
	XMLName             xml.Name                  `xml:"saml2:Subject"`
	BaseID              *BaseIDAbstractType       `xml:"BaseID"`
	NameID              *NameIDType               `xml:"saml2:NameID"`
	EncryptedID         *EncryptedElementType     `xml:"saml2:EncryptedID"`
	SubjectConfirmation []SubjectConfirmationType `xml:"saml2:SubjectConfirmation"`
	//InnerXml            string                    `xml:",innerxml"`
}

type SubjectConfirmationType struct {
	XMLName                 xml.Name                     `xml:"saml2:SubjectConfirmation"`
	Method                  string                       `xml:"Method,attr"`
	SubjectConfirmationData *SubjectConfirmationDataType `xml:"saml2:SubjectConfirmationData"`
	BaseID                  *BaseIDAbstractType          `xml:"BaseID"`
	NameID                  *NameIDType                  `xml:"saml2:NameID"`
	EncryptedID             *EncryptedElementType        `xml:"EncryptedID"`
	//InnerXml                string                       `xml:",innerxml"`
}

type SubjectConfirmationDataType struct {
	XMLName      xml.Name `xml:"saml2:SubjectConfirmationData"`
	NotBefore    string   `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr,omitempty"`
	Recipient    string   `xml:"Recipient,attr,omitempty"`
	InResponseTo string   `xml:"InResponseTo,attr,omitempty"`
	Address      string   `xml:"Address,attr,omitempty"`
	//InnerXml     string   `xml:",innerxml"`
}

type KeyInfoConfirmationDataType struct {
	XMLName      xml.Name `xml:"saml2:KeyInfoConfirmationData"`
	NotBefore    string   `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr,omitempty"`
	Recipient    string   `xml:"Recipient,attr,omitempty"`
	InResponseTo string   `xml:"InResponseTo,attr,omitempty"`
	Address      string   `xml:"Address,attr,omitempty"`
	//InnerXml     string   `xml:",innerxml"`
}

type ConditionsType struct {
	XMLName             xml.Name                  `xml:"saml2:Conditions"`
	NotBefore           string                    `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter        string                    `xml:"NotOnOrAfter,attr,omitempty"`
	Condition           []ConditionAbstractType   `xml:"Condition"`
	AudienceRestriction []AudienceRestrictionType `xml:"saml2:AudienceRestriction"`
	OneTimeUse          []OneTimeUseType          `xml:"saml2:OneTimeUse"`
	ProxyRestriction    []ProxyRestrictionType    `xml:"saml2:ProxyRestriction"`
	//InnerXml            string                    `xml:",innerxml"`
}

type ConditionAbstractType struct {
	XMLName xml.Name
	//InnerXml string `xml:",innerxml"`
}

type AudienceRestrictionType struct {
	XMLName  xml.Name `xml:"saml2:AudienceRestriction"`
	Audience []string `xml:"saml2:Audience"`
	//InnerXml string   `xml:",innerxml"`
}

type OneTimeUseType struct {
	XMLName xml.Name `xml:"saml2:OneTimeUse"`
	//InnerXml string   `xml:",innerxml"`
}

type ProxyRestrictionType struct {
	XMLName  xml.Name `xml:"saml2:ProxyRestriction"`
	Count    int      `xml:"Count,attr,omitempty"`
	Audience []string `xml:"saml2:Audience"`
	//InnerXml string   `xml:",innerxml"`
}

type AdviceType struct {
	XMLName            xml.Name               `xml:"saml2:Advice"`
	AssertionIDRef     []string               `xml:"AssertionIDRef"`
	AssertionURIRef    []string               `xml:"AssertionURIRef"`
	Assertion          []AssertionType        `xml:"saml2:Assertion"`
	EncryptedAssertion []EncryptedElementType `xml:"EncryptedAssertion"`
	//InnerXml           string                 `xml:",innerxml"`
}

type StatementAbstractType struct {
	XMLName xml.Name
	//InnerXml string `xml:",innerxml"`
}

type AuthnStatementType struct {
	XMLName             xml.Name             `xml:"saml2:AuthnStatement"`
	AuthnInstant        string               `xml:"AuthnInstant,attr"`
	SessionIndex        string               `xml:"SessionIndex,attr,omitempty"`
	SessionNotOnOrAfter string               `xml:"SessionNotOnOrAfter,attr,omitempty"`
	SubjectLocality     *SubjectLocalityType `xml:"saml2:SubjectLocality"`
	AuthnContext        AuthnContextType     `xml:"saml2:AuthnContext"`
	//InnerXml            string               `xml:",innerxml"`
}

type SubjectLocalityType struct {
	XMLName xml.Name `xml:"saml2:SubjectLocality"`
	Address string   `xml:"Address,attr,omitempty"`
	DNSName string   `xml:"DNSName,attr,omitempty"`
	//InnerXml string   `xml:",innerxml"`
}

type AuthnContextType struct {
	XMLName                 xml.Name `xml:"saml2:AuthnContext"`
	AuthenticatingAuthority []string `xml:"saml2:AuthenticatingAuthority"`
	AuthnContextClassRef    string   `xml:"saml2:AuthnContextClassRef,omitempty"`
	AuthnContextDecl        string   `xml:"saml2:AuthnContextDecl,omitempty"`
	AuthnContextDeclRef     string   `xml:"saml2:AuthnContextDeclRef,omitempty"`
	//InnerXml                string   `xml:",innerxml"`
}

type AuthzDecisionStatementType struct {
	XMLName  xml.Name      `xml:"saml2:AuthzDecisionStatement"`
	Resource string        `xml:"Resource,attr"`
	Decision DecisionType  `xml:"Decision,attr"`
	Action   []ActionType  `xml:"saml2:Action"`
	Evidence *EvidenceType `xml:"saml2:Evidence"`
	//	InnerXml string        `xml:",innerxml"`
}

type ActionType struct {
	XMLName   xml.Name `xml:"saml2:Action"`
	Namespace string   `xml:"Namespace,attr"`
	Text      string   `xml:",chardata"`
	//	InnerXml  string   `xml:",innerxml"`
}

type EvidenceType struct {
	XMLName            xml.Name               `xml:"saml2:Evidence"`
	AssertionIDRef     []string               `xml:"saml2:AssertionIDRef"`
	AssertionURIRef    []string               `xml:"saml2:AssertionURIRef"`
	Assertion          []AssertionType        `xml:"saml2:Assertion"`
	EncryptedAssertion []EncryptedElementType `xml:"saml2:EncryptedAssertion"`
	//	InnerXml           string                 `xml:",innerxml"`
}

type AttributeStatementType struct {
	XMLName   xml.Name         `xml:"saml2:AttributeStatement"`
	Attribute []*AttributeType `xml:"saml2:Attribute"`
	//InnerXml  string           `xml:",innerxml"`
}

type AttributeType struct {
	XMLName        xml.Name `xml:"saml2:Attribute"`
	Name           string   `xml:"Name,attr"`
	NameFormat     string   `xml:"NameFormat,attr,omitempty"`
	FriendlyName   string   `xml:"FriendlyName,attr,omitempty"`
	AttributeValue []string `xml:"saml2:AttributeValue"`
	//InnerXml       string   `xml:",innerxml"`
}

// XSD SimpleType declarations

type DecisionType string

const DecisionTypePermit DecisionType = "Permit"

const DecisionTypeDeny DecisionType = "Deny"

const DecisionTypeIndeterminate DecisionType = "Indeterminate"
