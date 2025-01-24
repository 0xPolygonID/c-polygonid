package verifiable

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type IssuerResolver struct {
}

const limitReaderBytes = 16 * 1024

func (IssuerResolver) Resolve(ctx context.Context,
	credentialStatus CredentialStatus) (out RevocationStatus, err error) {

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		credentialStatus.ID, http.NoBody)
	if err != nil {
		return out, err
	}
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer func() {
		err2 := httpResp.Body.Close()
		if err2 != nil && err == nil {
			err = err2
		}
	}()

	statusOK := httpResp.StatusCode >= 200 && httpResp.StatusCode < 300
	if !statusOK {
		return out, fmt.Errorf("unexpected status code: %d",
			httpResp.StatusCode)
	}

	limitReader := &io.LimitedReader{R: httpResp.Body, N: limitReaderBytes}

	respData, err := io.ReadAll(limitReader)
	if err != nil {
		return out, err
	}

	// Check if the body size exceeds the limit
	if limitReader.N <= 0 {
		return out, fmt.Errorf("response body size exceeds the limit of %d",
			limitReaderBytes)
	}

	err = json.Unmarshal(respData, &out)
	if err != nil {
		return out, err
	}
	return out, nil
}
