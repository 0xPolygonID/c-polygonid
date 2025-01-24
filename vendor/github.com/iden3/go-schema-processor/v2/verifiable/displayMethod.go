package verifiable

type DisplayMethodType string

type DisplayMethod struct {
	ID   string            `json:"id"`
	Type DisplayMethodType `json:"type"`
}
