package verifiable

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/pkg/errors"
)

type DIDResolver interface {
	Resolve(ctx context.Context, did *w3c.DID) (DIDDocument, error)
}

type HTTPDIDResolver struct {
	resolverURL      string
	customHTTPClient *http.Client
}

func (r HTTPDIDResolver) Resolve(ctx context.Context, did *w3c.DID) (out DIDDocument, err error) {
	type didResolutionResult struct {
		DIDDocument DIDDocument `json:"didDocument"`
	}
	res := &didResolutionResult{}

	var (
		resp       *http.Response
		httpClient *http.Client
	)

	httpClient = http.DefaultClient
	if r.customHTTPClient != nil {
		httpClient = r.customHTTPClient
	}
	didStr := did.String()
	didParts := strings.Split(didStr, "?")
	if len(didParts) == 2 {
		didEscaped := url.QueryEscape(didParts[0])
		didStr = fmt.Sprintf("%s?%s", didEscaped, didParts[1])
	}
	if err != nil {
		return out, err
	}
	resp, err = httpClient.Get(fmt.Sprintf("%s/%s", strings.Trim(r.resolverURL, "/"), didStr))

	if err != nil {
		return out, err
	}

	defer func() {
		err2 := resp.Body.Close()
		if err == nil {
			err = errors.WithStack(err2)
		}
	}()

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return out, err
	}

	return res.DIDDocument, nil
}
