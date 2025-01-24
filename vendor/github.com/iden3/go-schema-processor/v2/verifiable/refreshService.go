package verifiable

// RefreshServiceType represent refresh service types
type RefreshServiceType string

// RefreshService is struct that represents refresh service json-ld document
type RefreshService struct {
	ID   string             `json:"id"`
	Type RefreshServiceType `json:"type"`
}
