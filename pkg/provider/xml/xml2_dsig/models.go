package xml2_dsig

import "encoding/xml"

type SignatureType struct {
	XMLName        xml.Name           `xml:"ds:Signature"`
	Ds             string             `xml:"xmlns:ds,attr"`
	Id             string             `xml:"Id,attr,omitempty"`
	SignedInfo     SignedInfoType     `xml:"ds:SignedInfo"`
	SignatureValue SignatureValueType `xml:"ds:SignatureValue"`
	KeyInfo        *KeyInfoType       `xml:"ds:KeyInfo"`
	Object         []ObjectType       `xml:"ds:Object"`
	//InnerXml       string             `xml:",innerxml"`
}

type SignatureValueType struct {
	XMLName xml.Name `xml:"ds:SignatureValue"`
	Id      string   `xml:"Id,attr,omitempty"`
	Text    string   `xml:",chardata"`
	//InnerXml string   `xml:",innerxml"`
}

type SignedInfoType struct {
	XMLName                xml.Name                   `xml:"ds:SignedInfo"`
	Id                     string                     `xml:"Id,attr,omitempty"`
	CanonicalizationMethod CanonicalizationMethodType `xml:"ds:CanonicalizationMethod"`
	SignatureMethod        SignatureMethodType        `xml:"ds:SignatureMethod"`
	Reference              []ReferenceType            `xml:"ds:Reference"`
	//InnerXml               string                     `xml:",innerxml"`
}

type CanonicalizationMethodType struct {
	XMLName   xml.Name `xml:"ds:CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
	//InnerXml  string   `xml:",innerxml"`
}

type SignatureMethodType struct {
	XMLName          xml.Name              `xml:"ds:SignatureMethod"`
	Algorithm        string                `xml:"Algorithm,attr"`
	HMACOutputLength *HMACOutputLengthType `xml:",any"`
	//InnerXml         string                `xml:",innerxml"`
}

type ReferenceType struct {
	XMLName      xml.Name         `xml:"ds:Reference"`
	Id           string           `xml:"Id,attr,omitempty"`
	URI          string           `xml:"URI,attr,omitempty"`
	Type         string           `xml:"Type,attr,omitempty"`
	Transforms   *TransformsType  `xml:"ds:Transforms"`
	DigestMethod DigestMethodType `xml:"ds:DigestMethod"`
	DigestValue  DigestValueType  `xml:"ds:DigestValue"`
	//InnerXml     string           `xml:",innerxml"`
}

type TransformsType struct {
	XMLName   xml.Name        `xml:"ds:Transforms"`
	Transform []TransformType `xml:",any"`
	//InnerXml  string          `xml:",innerxml"`
}

type TransformType struct {
	XMLName   xml.Name `xml:"ds:Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
	XPath     []string `xml:"XPath"`
	//InnerXml  string   `xml:",innerxml"`
}

type DigestMethodType struct {
	XMLName   xml.Name `xml:"ds:DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
	//InnerXml  string   `xml:",innerxml"`
}

type KeyInfoType struct {
	XMLName         xml.Name
	Id              string                `xml:"Id,attr,omitempty"`
	KeyName         []string              `xml:"ds:KeyName"`
	KeyValue        []KeyValueType        `xml:"ds:KeyValue"`
	RetrievalMethod []RetrievalMethodType `xml:"ds:RetrievalMethod"`
	X509Data        []X509DataType        `xml:"ds:X509Data"`
	PGPData         []PGPDataType         `xml:"ds:PGPData"`
	SPKIData        []SPKIDataType        `xml:"ds:SPKIData"`
	MgmtData        []string              `xml:"ds:MgmtData"`
	//InnerXml        string                `xml:",innerxml"`
}

type KeyValueType struct {
	XMLName     xml.Name         `xml:"ds:KeyValue"`
	DSAKeyValue *DSAKeyValueType `xml:"ds:DSAKeyValue"`
	RSAKeyValue *RSAKeyValueType `xml:"ds:RSAKeyValue"`
	//InnerXml    string           `xml:",innerxml"`
}

type RetrievalMethodType struct {
	XMLName    xml.Name        `xml:"ds:RetrievalMethod"`
	URI        string          `xml:"URI,attr"`
	Type       string          `xml:"Type,attr,omitempty"`
	Transforms *TransformsType `xml:",any"`
	//InnerXml   string          `xml:",innerxml"`
}

type X509DataType struct {
	XMLName          xml.Name              `xml:"ds:X509Data"`
	X509IssuerSerial *X509IssuerSerialType `xml:"ds:X509IssuerSerial"`
	X509SKI          string                `xml:"ds:X509SKI,omitempty"`
	X509SubjectName  string                `xml:"ds:X509SubjectName,omitempty"`
	X509Certificate  string                `xml:"ds:X509Certificate"`
	X509CRL          string                `xml:"ds:X509CRL,omitempty"`
	//InnerXml         string                `xml:",innerxml"`
}

type X509IssuerSerialType struct {
	XMLName          xml.Name `xml:"ds:X509IssuerSerial"`
	X509IssuerName   string   `xml:"ds:X509IssuerName"`
	X509SerialNumber int64    `xml:"ds:X509SerialNumber"`
	//InnerXml         string   `xml:",innerxml"`
}

type PGPDataType struct {
	XMLName      xml.Name `xml:"ds:PGPData"`
	PGPKeyID     string   `xml:"PGPKeyID"`
	PGPKeyPacket string   `xml:"PGPKeyPacket"`
	//InnerXml     string   `xml:",innerxml"`
}

type SPKIDataType struct {
	XMLName  xml.Name `xml:"ds:SPKIData"`
	SPKISexp string   `xml:",any"`
	//InnerXml string   `xml:",innerxml"`
}

type ObjectType struct {
	XMLName  xml.Name `xml:"ds:Object"`
	Id       string   `xml:"Id,attr,omitempty"`
	MimeType string   `xml:"MimeType,attr,omitempty"`
	Encoding string   `xml:"Encoding,attr,omitempty"`
	//InnerXml string   `xml:",innerxml"`
}

type ManifestType struct {
	XMLName   xml.Name        `xml:"Manifest"`
	Id        string          `xml:"Id,attr,omitempty"`
	Reference []ReferenceType `xml:",any"`
	//InnerXml  string          `xml:",innerxml"`
}

type SignaturePropertiesType struct {
	XMLName           xml.Name                `xml:"ds:SignatureProperties"`
	Id                string                  `xml:"Id,attr,omitempty"`
	SignatureProperty []SignaturePropertyType `xml:",any"`
	//InnerXml          string                  `xml:",innerxml"`
}

type SignaturePropertyType struct {
	XMLName xml.Name `xml:"ds:SignatureProperty"`
	Target  string   `xml:"Target,attr"`
	Id      string   `xml:"Id,attr,omitempty"`
	//InnerXml string   `xml:",innerxml"`
}

type DSAKeyValueType struct {
	XMLName xml.Name      `xml:"ds:DSAKeyValue"`
	G       *CryptoBinary `xml:"G"`
	Y       CryptoBinary  `xml:"Y"`
	J       *CryptoBinary `xml:"J"`
	//InnerXml string        `xml:",innerxml"`
}

type RSAKeyValueType struct {
	XMLName  xml.Name     `xml:"ds:RSAKeyValue"`
	Modulus  CryptoBinary `xml:"ds:Modulus"`
	Exponent CryptoBinary `xml:"ds:Exponent"`
	//InnerXml string       `xml:",innerxml"`
}

type CryptoBinary string

type DigestValueType string

type HMACOutputLengthType int64

const (
	DigestMethodSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestMethodSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestMethodSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)
