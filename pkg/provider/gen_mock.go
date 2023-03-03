package provider

//go:generate mockgen -package mock -destination ./mock/storage.mock.go github.com/tzrd/saml/pkg/provider Storage
//go:generate mockgen -package mock -destination ./mock/idpstorage.mock.go github.com/tzrd/saml/pkg/provider IDPStorage
//go:generate mockgen -package mock -destination ./mock/authrequestint.mock.go github.com/tzrd/saml/pkg/provider/models AuthRequestInt
