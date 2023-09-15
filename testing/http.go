package testing

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockedRouterTripper struct {
	t         testing.TB
	routes    map[string]string
	seenURLsM sync.Mutex
	seenURLs  map[string]struct{}
}

func (m *mockedRouterTripper) RoundTrip(
	request *http.Request) (*http.Response, error) {

	urlStr := request.URL.String()
	routerKey := urlStr
	rr := httptest.NewRecorder()
	var postData []byte
	if request.Method == http.MethodPost {
		var err error
		postData, err = io.ReadAll(request.Body)
		if err != nil {
			http.Error(rr, err.Error(), http.StatusInternalServerError)

			httpResp := rr.Result()
			httpResp.Request = request
			return httpResp, nil
		}
		if len(postData) > 0 {
			routerKey += "%%%" + string(postData)
		}
	}

	respFile, ok := m.routes[routerKey]
	if !ok {
		var requestBodyStr = string(postData)
		if requestBodyStr == "" {
			m.t.Errorf("unexpected http request: %v", urlStr)
		} else {
			m.t.Errorf("unexpected http request: %v\nBody: %v",
				urlStr, requestBodyStr)
		}
		rr2 := httptest.NewRecorder()
		rr2.WriteHeader(http.StatusNotFound)
		httpResp := rr2.Result()
		httpResp.Request = request
		return httpResp, nil
	}

	m.seenURLsM.Lock()
	if m.seenURLs == nil {
		m.seenURLs = make(map[string]struct{})
	}
	m.seenURLs[routerKey] = struct{}{}
	m.seenURLsM.Unlock()

	usedHttpResponsesM.Lock()
	usedHttpResponses[respFile] = struct{}{}
	usedHttpResponsesM.Unlock()

	http.ServeFile(rr, request, respFile)

	rr2 := rr.Result()
	rr2.Request = request
	return rr2, nil
}

type mockHTTPClientOptions struct {
	ignoreUntouchedURLs bool
}

type MockHTTPClientOption func(*mockHTTPClientOptions)

func IgnoreUntouchedURLs() MockHTTPClientOption {
	return func(opts *mockHTTPClientOptions) {
		opts.ignoreUntouchedURLs = true
	}
}

func MockHTTPClient(t testing.TB, routes map[string]string,
	opts ...MockHTTPClientOption) func() {

	var op mockHTTPClientOptions
	for _, o := range opts {
		o(&op)
	}

	oldRoundTripper := http.DefaultTransport
	transport := &mockedRouterTripper{t: t, routes: routes}
	http.DefaultTransport = transport
	return func() {
		http.DefaultTransport = oldRoundTripper

		if !op.ignoreUntouchedURLs {
			for u := range routes {
				_, ok := transport.seenURLs[u]
				assert.True(t, ok,
					"found a URL in routes that we did not touch: %v", u)
			}
		}
	}
}

var usedHttpResponses = make(map[string]struct{})
var usedHttpResponsesM sync.Mutex

// CheckForRedundantHttpresps checks that all files in `dir` directory
// with `prefix` prefix were touched by mocked http client. Return false
// if found redundant file there were not requested during tests.
func CheckForRedundantHttpresps(dir string, prefix string) bool {
	dir = strings.TrimRight(dir, "/")

	files, err := os.ReadDir(dir)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error reading testdata dir: %v\n", err)
		return false
	}

	usedHttpResponsesM.Lock()
	defer usedHttpResponsesM.Unlock()

	for _, file := range files {
		fName := file.Name()
		if !strings.HasPrefix(fName, prefix) {
			continue
		}

		_, ok := usedHttpResponses[dir+"/"+fName]
		if !ok {
			fmt.Printf("found file %v that were not used in tests\n", fName)
			return false
		}
	}

	return true
}
