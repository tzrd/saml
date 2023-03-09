package saml2p

import (
	"encoding/xml"

	"github.com/tzrd/saml/pkg/provider/xml/saml"
	"github.com/tzrd/saml/pkg/provider/xml/xml_dsig"
)

type RequestAbstractType struct {
	XMLName      xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:RequestAbstract"`
	Id           string                  `xml:"ID,attr"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	//InnerXml     string                  `xml:",innerxml"`
}

type ExtensionsType struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:Extensions"`
	//InnerXml string   `xml:",innerxml"`
}

type StatusResponseType struct {
	XMLName      xml.Name                `xml:"saml2p:StatusResponse"`
	Id           string                  `xml:"ID,attr"`
	InResponseTo string                  `xml:"InResponseTo,attr,omitempty"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	Status       StatusType              `xml:"Status"`
	//InnerXml     string                  `xml:",innerxml"`
}

type StatusType struct {
	XMLName       xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2:Status"`
	StatusCode    StatusCodeType    `xml:"StatusCode"`
	StatusMessage string            `xml:"StatusMessage,omitempty"`
	StatusDetail  *StatusDetailType `xml:"StatusDetail"`
	//InnerXml      string            `xml:",innerxml"`
}

type StatusCodeType struct {
	XMLName    xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:StatusCode"`
	Value      string          `xml:"Value,attr"`
	StatusCode *StatusCodeType `xml:",any"`
	//InnerXml   string          `xml:",innerxml"`
}

type StatusDetailType struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:StatusDetail"`
	//InnerXml string   `xml:",innerxml"`
}

type AssertionIDRequestType struct {
	XMLName        xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:protocol AssertionIDRequest"`
	Id             string                  `xml:"ID,attr"`
	Version        string                  `xml:"Version,attr"`
	IssueInstant   string                  `xml:"IssueInstant,attr"`
	Destination    string                  `xml:"Destination,attr,omitempty"`
	Consent        string                  `xml:"Consent,attr,omitempty"`
	AssertionIDRef []string                `xml:"AssertionIDRef"`
	Issuer         *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature      *xml_dsig.SignatureType `xml:"Signature"`
	Extensions     *ExtensionsType         `xml:"saml2p:Extensions"`
	//InnerXml       string                  `xml:",innerxml"`
}

type SubjectQueryAbstractType struct {
	XMLName      xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:SubjectQueryAbstract"`
	Id           string                  `xml:"ID,attr"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Subject      saml.SubjectType        `xml:"saml2:Subject"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	//InnerXml     string                  `xml:",innerxml"`
}

type AuthnQueryType struct {
	XMLName               xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:AuthnQuery"`
	SessionIndex          string                     `xml:"SessionIndex,attr,omitempty"`
	Id                    string                     `xml:"ID,attr"`
	Version               string                     `xml:"Version,attr"`
	IssueInstant          string                     `xml:"IssueInstant,attr"`
	Destination           string                     `xml:"Destination,attr,omitempty"`
	Consent               string                     `xml:"Consent,attr,omitempty"`
	RequestedAuthnContext *RequestedAuthnContextType `xml:"saml2p:RequestedAuthnContext"`
	Subject               saml.SubjectType           `xml:"saml2:Subject"`
	Issuer                *saml.NameIDType           `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature             *xml_dsig.SignatureType    `xml:"Signature"`
	Extensions            *ExtensionsType            `xml:"saml2p:Extensions"`
	//InnerXml              string                     `xml:",innerxml"`
}

type RequestedAuthnContextType struct {
	XMLName              xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:RequestedAuthnContext"`
	Comparison           AuthnContextComparisonType `xml:"Comparison,attr,omitempty"`
	AuthnContextClassRef []string                   `xml:"AuthnContextClassRef"`
	AuthnContextDeclRef  []string                   `xml:"AuthnContextDeclRef"`
	//InnerXml             string                     `xml:",innerxml"`
}

type AttributeQueryType struct {
	XMLName      xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:AttributeQuery"`
	Id           string                  `xml:"ID,attr"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Attribute    []saml.AttributeType    `xml:"saml2:Attribute"`
	Subject      saml.SubjectType        `xml:"saml2:Subject"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	//InnerXml     string                  `xml:",innerxml"`
}

type AuthzDecisionQueryType struct {
	XMLName      xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:AuthzDecisionQuery"`
	Resource     string                  `xml:"Resource,attr"`
	Id           string                  `xml:"ID,attr"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Action       []saml.ActionType       `xml:"saml2:Action"`
	Evidence     *saml.EvidenceType      `xml:"saml2:Evidence"`
	Subject      saml.SubjectType        `xml:"saml2:Subject"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	//InnerXml     string                  `xml:",innerxml"`
}

type AuthnRequestType struct {
	XMLName                        xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:AuthnRequest"`
	ForceAuthn                     string                     `xml:"ForceAuthn,attr,omitempty"`
	IsPassive                      string                     `xml:"IsPassive,attr,omitempty"`
	ProtocolBinding                string                     `xml:"ProtocolBinding,attr,omitempty"`
	AssertionConsumerServiceIndex  string                     `xml:"AssertionConsumerServiceIndex,attr,omitempty"`
	AssertionConsumerServiceURL    string                     `xml:"AssertionConsumerServiceURL,attr,omitempty"`
	AttributeConsumingServiceIndex string                     `xml:"AttributeConsumingServiceIndex,attr,omitempty"`
	ProviderName                   string                     `xml:"ProviderName,attr,omitempty"`
	Id                             string                     `xml:"ID,attr"`
	Version                        string                     `xml:"Version,attr"`
	IssueInstant                   string                     `xml:"IssueInstant,attr"`
	Destination                    string                     `xml:"Destination,attr,omitempty"`
	Consent                        string                     `xml:"Consent,attr,omitempty"`
	Subject                        *saml.SubjectType          `xml:"saml2:Subject"`
	NameIDPolicy                   *NameIDPolicyType          `xml:"saml2p:NameIDPolicy"`
	Conditions                     *saml.ConditionsType       `xml:"saml2:Conditions"`
	RequestedAuthnContext          *RequestedAuthnContextType `xml:"saml2p:RequestedAuthnContext"`
	Scoping                        *ScopingType               `xml:"saml2p:Scoping"`
	Issuer                         *saml.NameIDType           `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature                      *xml_dsig.SignatureType    `xml:"Signature"`
	Extensions                     *ExtensionsType            `xml:"saml2p:Extensions"`
	//InnerXml                       string                     `xml:",innerxml"`
}

type NameIDPolicyType struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:NameIDPolicy"`
	Format          string   `xml:"Format,attr,omitempty"`
	SPNameQualifier string   `xml:"SPNameQualifier,attr,omitempty"`
	AllowCreate     bool     `xml:"AllowCreate,attr,omitempty"`
	//	InnerXml        string   `xml:",innerxml"`
}

type ScopingType struct {
	XMLName     xml.Name     `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:Scoping"`
	ProxyCount  int          `xml:"ProxyCount,attr,omitempty"`
	IDPList     *IDPListType `xml:"saml2p:IDPList"`
	RequesterID []string     `xml:"RequesterID"`
	//InnerXml    string       `xml:",innerxml"`
}

type IDPListType struct {
	XMLName     xml.Name       `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:IDPList"`
	IDPEntry    []IDPEntryType `xml:"saml2p:IDPEntry"`
	GetComplete string         `xml:"GetComplete"`
	//InnerXml    string         `xml:",innerxml"`
}

type IDPEntryType struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:IDPEntry"`
	ProviderID string   `xml:"ProviderID,attr"`
	Name       string   `xml:"Name,attr,omitempty"`
	Loc        string   `xml:"Loc,attr,omitempty"`
	//InnerXml   string   `xml:",innerxml"`
}

type ResponseType struct {
	XMLName      xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:Response"`
	Id           string                  `xml:"ID,attr"`
	InResponseTo string                  `xml:"InResponseTo,attr,omitempty"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	Status       StatusType              `xml:"saml2p:Status"`
	Assertion    saml.AssertionType      `xml:"saml2:Assertion"`
	//InnerXml     string                  `xml:",innerxml"`
}

type ArtifactResolveType struct {
	XMLName      xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:ArtifactResolve"`
	Id           string                  `xml:"ID,attr"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Artifact     string                  `xml:"Artifact"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	//InnerXml     string                  `xml:",innerxml"`
}

type ArtifactResponseType struct {
	XMLName      xml.Name                `xml:"saml2p:ArtifactResponse"`
	Id           string                  `xml:"ID,attr"`
	InResponseTo string                  `xml:"InResponseTo,attr,omitempty"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	Status       StatusType              `xml:"saml2p:Status"`
	//InnerXml     string                  `xml:",innerxml"`
}

type ManageNameIDRequestType struct {
	XMLName        xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:ManageNameIDRequest"`
	Id             string                     `xml:"ID,attr"`
	Version        string                     `xml:"Version,attr"`
	IssueInstant   string                     `xml:"IssueInstant,attr"`
	Destination    string                     `xml:"Destination,attr,omitempty"`
	Consent        string                     `xml:"Consent,attr,omitempty"`
	NameID         *saml.NameIDType           `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:NameID"`
	EncryptedID    *saml.EncryptedElementType `xml:"EncryptedID"`
	NewID          string                     `xml:"NewID"`
	NewEncryptedID *saml.EncryptedElementType `xml:"NewEncryptedID"`
	Terminate      *TerminateType             `xml:"saml2p:Terminate"`
	Issuer         *saml.NameIDType           `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature      *xml_dsig.SignatureType    `xml:"Signature"`
	Extensions     *ExtensionsType            `xml:"saml2p:Extensions"`
	//InnerXml       string                     `xml:",innerxml"`
}

type TerminateType struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Terminate"`
	//InnerXml string   `xml:",innerxml"`
}

type LogoutRequestType struct {
	XMLName      xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:LogoutRequest"`
	Reason       string                     `xml:"Reason,attr,omitempty"`
	NotOnOrAfter string                     `xml:"NotOnOrAfter,attr,omitempty"`
	Id           string                     `xml:"ID,attr"`
	Version      string                     `xml:"Version,attr"`
	IssueInstant string                     `xml:"IssueInstant,attr"`
	Destination  string                     `xml:"Destination,attr,omitempty"`
	Consent      string                     `xml:"Consent,attr,omitempty"`
	SessionIndex []string                   `xml:"SessionIndex"`
	BaseID       *saml.BaseIDAbstractType   `xml:"BaseID"`
	NameID       *saml.NameIDType           `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:NameID"`
	EncryptedID  *saml.EncryptedElementType `xml:"EncryptedID"`
	Issuer       *saml.NameIDType           `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType    `xml:"Signature"`
	Extensions   *ExtensionsType            `xml:"saml2p:Extensions"`
	//	InnerXml     string                     `xml:",innerxml"`
}

type LogoutResponseType struct {
	XMLName      xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:LogoutResponse"`
	Id           string                  `xml:"ID,attr"`
	InResponseTo string                  `xml:"InResponseTo,attr,omitempty"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	Status       StatusType              `xml:"Status"`
	//InnerXml     string                     `xml:",innerxml"`
}

type NameIDMappingRequestType struct {
	XMLName      xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:protocol saml2p:NameIDMappingRequest"`
	Id           string                     `xml:"ID,attr"`
	Version      string                     `xml:"Version,attr"`
	IssueInstant string                     `xml:"IssueInstant,attr"`
	Destination  string                     `xml:"Destination,attr,omitempty"`
	Consent      string                     `xml:"Consent,attr,omitempty"`
	NameIDPolicy NameIDPolicyType           `xml:"saml2p:NameIDPolicy"`
	BaseID       *saml.BaseIDAbstractType   `xml:"BaseID"`
	NameID       *saml.NameIDType           `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:NameID"`
	EncryptedID  *saml.EncryptedElementType `xml:"EncryptedID"`
	Issuer       *saml.NameIDType           `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType    `xml:"Signature"`
	Extensions   *ExtensionsType            `xml:"saml2p:Extensions"`
	//InnerXml     string                     `xml:",innerxml"`
}

type NameIDMappingResponseType struct {
	XMLName      xml.Name                `xml:"saml2p:NameIDMappingResponse"`
	Id           string                  `xml:"ID,attr"`
	InResponseTo string                  `xml:"InResponseTo,attr,omitempty"`
	Version      string                  `xml:"Version,attr"`
	IssueInstant string                  `xml:"IssueInstant,attr"`
	Destination  string                  `xml:"Destination,attr,omitempty"`
	Consent      string                  `xml:"Consent,attr,omitempty"`
	Issuer       *saml.NameIDType        `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml2:Issuer"`
	Signature    *xml_dsig.SignatureType `xml:"Signature"`
	Extensions   *ExtensionsType         `xml:"saml2p:Extensions"`
	Status       StatusType              `xml:"saml2p:Status"`
	//InnerXml     string                  `xml:",innerxml"`
}

// XSD SimpleType declarations

type AuthnContextComparisonType string

const AuthnContextComparisonTypeExact AuthnContextComparisonType = "exact"

const AuthnContextComparisonTypeMinimum AuthnContextComparisonType = "minimum"

const AuthnContextComparisonTypeMaximum AuthnContextComparisonType = "maximum"

const AuthnContextComparisonTypeBetter AuthnContextComparisonType = "better"
