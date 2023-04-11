package xml_test

import (
	"testing"

	"github.com/tzrd/saml/pkg/provider/xml"
)

type XML struct {
	InnerXml string `xml:",innerxml"`
}

type Response struct {
	Xmlns    string `xml:"xmlns,attr"`
	InnerXml string `xml:",innerxml"`
}

func Test_XmlMarshal(t *testing.T) {
	type res struct {
		metadata string
		err      bool
	}

	tests := []struct {
		name string
		arg  string
		res  res
	}{
		{
			name: "xml struct",
			arg:  "<test></test>",
			res: res{
				metadata: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<XML><test></test></XML>",
				err:      false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xmlStruct := XML{InnerXml: tt.arg}

			xmlStr, err := xml.Marshal(xmlStruct)
			if (err != nil) != tt.res.err {
				t.Errorf("Marshal() error: %v", err)
				return
			}
			if xmlStr != tt.res.metadata {
				t.Errorf("Marshal() error expected: %v, got %v", tt.res.metadata, xmlStr)
				return
			}
		})
	}
}

func Test_SAML2_XmlMarshal(t *testing.T) {
	type res struct {
		metadata string
		err      bool
	}

	tests := []struct {
		name string
		arg  string
		res  res
	}{
		{
			name: "response struct",
			arg:  "<Issuer></Issuer>",
			res: res{
				metadata: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\"><Issuer></Issuer></Response>",
				err:      false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xmlStruct := Response{
				Xmlns:    "urn:oasis:names:tc:SAML:2.0:protocol",
				InnerXml: tt.arg,
			}

			xmlStr, err := xml.Marshal(xmlStruct)
			if (err != nil) != tt.res.err {
				t.Errorf("Marshal() error: %v", err)
				return
			}
			if xmlStr != tt.res.metadata {
				t.Errorf("Marshal() error expected: %v, got %v", tt.res.metadata, xmlStr)
				return
			}
		})
	}
}
