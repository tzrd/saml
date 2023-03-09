package soap

import (
	"encoding/xml"

	"github.com/tzrd/saml/pkg/provider/xml/saml2p"
)

type ArtifactResolveEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    ArtifactResolveBody
}

type ArtifactResolveBody struct {
	XMLName         xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	ArtifactResolve *saml2p.ArtifactResolveType
}

type ArtifactResponseEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    ArtifactResponseBody
}

type ArtifactResponseBody struct {
	XMLName          xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	ArtifactResponse *saml2p.ArtifactResponseType
}

type AttributeQueryEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    AttributeQueryBody
}

type AttributeQueryBody struct {
	XMLName        xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	AttributeQuery *saml2p.AttributeQueryType
}

type ResponseEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    ResponseBody
}

type ResponseBody struct {
	XMLName  xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Response *saml2p.ResponseType
}
