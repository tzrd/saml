package soap

import (
	"encoding/xml"

	"github.com/tzrd/saml/pkg/provider/xml/samlp2"
)

type ArtifactResolveEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    ArtifactResolveBody
}

type ArtifactResolveBody struct {
	XMLName         xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	ArtifactResolve *samlp2.ArtifactResolveType
}

type ArtifactResponseEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    ArtifactResponseBody
}

type ArtifactResponseBody struct {
	XMLName          xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	ArtifactResponse *samlp2.ArtifactResponseType
}

type AttributeQueryEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    AttributeQueryBody
}

type AttributeQueryBody struct {
	XMLName        xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	AttributeQuery *samlp2.AttributeQueryType
}

type ResponseEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    ResponseBody
}

type ResponseBody struct {
	XMLName  xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Response *samlp2.ResponseType
}
