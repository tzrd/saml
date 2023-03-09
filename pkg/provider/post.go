package provider

import (
	"context"
	"encoding/base64"
	"reflect"

	"github.com/tzrd/saml/pkg/provider/serviceprovider"
	"github.com/tzrd/saml/pkg/provider/signature"
	"github.com/tzrd/saml/pkg/provider/xml/md"
	"github.com/tzrd/saml/pkg/provider/xml/samlp2"
	"github.com/tzrd/saml/pkg/provider/xml/xml_dsig"
)

func signaturePostProvided(
	signatureF func() *xml_dsig.SignatureType,
) func() bool {
	return func() bool {
		signatureV := signatureF()

		return signatureV != nil &&
			!reflect.DeepEqual(signatureV.SignatureValue, xml_dsig.SignatureValueType{}) &&
			signatureV.SignatureValue.Text != ""
	}
}
func signaturePostVerificationNecessary(
	idpMetadataF func() *md.IDPSSODescriptorType,
	spMetadataF func() *md.EntityDescriptorType,
	signatureF func() *xml_dsig.SignatureType,
	protocolBinding func() string,
) func() bool {
	return func() bool {
		spMeta := spMetadataF()
		idpMeta := idpMetadataF()

		return ((spMeta == nil || spMeta.SPSSODescriptor == nil || spMeta.SPSSODescriptor.AuthnRequestsSigned == "true") ||
			(idpMeta == nil || idpMeta.WantAuthnRequestsSigned == "true") ||
			signaturePostProvided(signatureF)()) &&
			protocolBinding() == PostBinding
	}
}

func verifyPostSignature(
	authRequestF func() string,
	spF func() *serviceprovider.ServiceProvider,
	errF func(error),
) func() error {
	return func() error {
		sp := spF()

		data, err := base64.StdEncoding.DecodeString(authRequestF())
		if err != nil {
			errF(err)
			return err
		}

		if err := sp.ValidatePostSignature(string(data)); err != nil {
			errF(err)
			return err
		}
		return nil
	}
}

func createPostSignature(
	ctx context.Context,
	samlResponse *samlp2.ResponseType,
	idp *IdentityProvider,
) error {
	cert, key, err := getResponseCert(ctx, idp.storage)
	if err != nil {
		return err
	}

	signer, err := signature.GetSigner(cert, key, idp.conf.SignatureAlgorithm)
	if err != nil {
		return err
	}

	sig, err := signature.Create(signer, samlResponse.Assertion)
	if err != nil {
		return err
	}

	samlResponse.Assertion.Signature = sig
	return nil
}
