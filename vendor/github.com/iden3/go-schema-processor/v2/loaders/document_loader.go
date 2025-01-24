package loaders

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/pquerna/cachecontrol"
)

const (
	// An HTTP Accept header that prefers JSONLD.
	acceptHeader = "application/ld+json, application/json;q=0.9, application/javascript;q=0.5, text/javascript;q=0.5, text/plain;q=0.2, */*;q=0.1"

	// JSON-LD link header rel
	linkHeaderRel = "http://www.w3.org/ns/json-ld#context"
)

var rApplicationJSON = regexp.MustCompile(`^application/(\w*\+)?json$`)

var ErrCacheMiss = errors.New("cache miss")

type CacheEngine interface {
	Get(key string) (doc *ld.RemoteDocument, expireTime time.Time, err error)
	Set(key string, doc *ld.RemoteDocument, expireTime time.Time) error
}

type IPFSClient interface {
	Cat(url string) (io.ReadCloser, error)
}

type documentLoader struct {
	ipfsCli     IPFSClient // @formatter:off : Goland bug
	ipfsGW      string
	cacheEngine CacheEngine
	noCache     bool
	httpClient  *http.Client
}

type DocumentLoaderOption func(*documentLoader)

func WithCacheEngine(cacheEngine CacheEngine) DocumentLoaderOption {
	return func(loader *documentLoader) {
		if cacheEngine == nil {
			loader.noCache = true
			return
		}

		loader.cacheEngine = cacheEngine
	}
}

func WithHTTPClient(httpClient *http.Client) DocumentLoaderOption {
	return func(loader *documentLoader) {
		loader.httpClient = httpClient
	}
}

// NewDocumentLoader creates a new document loader with a cache for http.
// ipfs cache is not implemented yet.
func NewDocumentLoader(ipfsCli IPFSClient, ipfsGW string,
	opts ...DocumentLoaderOption) ld.DocumentLoader {
	loader := &documentLoader{
		ipfsCli: ipfsCli,
		ipfsGW:  ipfsGW,
	}

	for _, opt := range opts {
		opt(loader)
	}

	if loader.cacheEngine == nil && !loader.noCache {
		// Should not be errors if we call NewMemoryCacheEngine without options
		loader.cacheEngine, _ = NewMemoryCacheEngine()
	}

	return loader
}

func (d *documentLoader) LoadDocument(
	u string) (doc *ld.RemoteDocument, err error) {

	const ipfsPrefix = "ipfs://"

	switch {
	case strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://"):
		return d.loadDocumentFromHTTP(u)

	case strings.HasPrefix(u, ipfsPrefix):
		// supported URLs:
		// ipfs://<cid>/dir/schema.json
		// ipfs://<cid>

		doc = &ld.RemoteDocument{DocumentURL: u}

		// strip ipfs:// prefix
		u = u[len(ipfsPrefix):]

		switch {
		case d.ipfsCli != nil:
			doc.Document, err = d.loadDocumentFromIPFSNode(u)
		case d.ipfsGW != "":
			doc.Document, err = d.loadDocumentFromIPFSGW(u)
		default:
			err = ld.NewJsonLdError(ld.LoadingDocumentFailed,
				errors.New("ipfs is not configured"))
		}
		if err != nil {
			return nil, err
		}

		return doc, nil

	default:
		err = errors.New("unsupported URL schema")
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
	}
}

func (d *documentLoader) loadDocumentFromIPFSNode(
	ipfsURL string) (document any, err error) {

	if d.ipfsCli == nil {
		return nil, errors.New("ipfs is not configured")
	}

	var r io.ReadCloser
	r, err = d.ipfsCli.Cat(ipfsURL)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
	}
	defer func() {
		err2 := r.Close()
		if err == nil {
			err = err2
		}
	}()

	return ld.DocumentFromReader(r)
}

func (d *documentLoader) loadDocumentFromIPFSGW(
	ipfsURL string) (any, error) {

	ipfsURL = strings.TrimRight(d.ipfsGW, "/") + "/ipfs/" +
		strings.TrimLeft(ipfsURL, "/")
	doc, err := d.loadDocumentFromHTTP(ipfsURL)
	if err != nil {
		return nil, err
	}
	return doc.Document, nil
}

func (d *documentLoader) loadDocumentFromHTTP(
	u string) (*ld.RemoteDocument, error) {

	var doc *ld.RemoteDocument
	var cacheFound bool
	var err error

	// We use shouldCache, and expireTime at the end of this method to create
	// an object to store in the cache. Set them to sane default values now
	shouldCache := false
	var expireTime time.Time

	if d.cacheEngine != nil {
		doc, expireTime, err = d.cacheEngine.Get(u)
		switch {
		case errors.Is(err, ErrCacheMiss):
			cacheFound = false
		case err != nil:
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		default:
			cacheFound = true
		}
	}

	now := time.Now()

	// First we check if we hit in the cache, and the cache entry is valid
	// We need to check if ExpireTime >= now, so we negate the comparison below
	if cacheFound && expireTime.After(now) {
		return doc, nil
	}

	req, err := http.NewRequest("GET", u, http.NoBody)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
	}
	// We prefer application/ld+json, but fallback to application/json
	// or whatever is available
	req.Header.Add("Accept", acceptHeader)

	httpClient := d.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed,
			fmt.Sprintf("Bad response status code: %d",
				res.StatusCode))
	}

	doc = &ld.RemoteDocument{DocumentURL: res.Request.URL.String()}

	contentType := res.Header.Get("Content-Type")
	linkHeader := res.Header.Get("Link")

	if len(linkHeader) > 0 {
		parsedLinkHeader := ld.ParseLinkHeader(linkHeader)
		contextLink := parsedLinkHeader[linkHeaderRel]
		if contextLink != nil && contentType != ld.ApplicationJSONLDType {
			if len(contextLink) > 1 {
				return nil, ld.NewJsonLdError(ld.MultipleContextLinkHeaders,
					nil)
			} else if len(contextLink) == 1 {
				doc.ContextURL = contextLink[0]["target"]
			}
		}

		// If content-type is not application/ld+json, nor any other +json
		// and a link with rel=alternate and type='application/ld+json' is found,
		// use that instead
		alternateLink := parsedLinkHeader["alternate"]
		if len(alternateLink) > 0 &&
			alternateLink[0]["type"] == ld.ApplicationJSONLDType &&
			!rApplicationJSON.MatchString(contentType) {

			finalURL := ld.Resolve(u, alternateLink[0]["target"])
			doc, err = d.LoadDocument(finalURL)
			if err != nil {
				return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
			}
		}
	}

	reasons, resExpireTime, err := cachecontrol.CachableResponse(req, res,
		cachecontrol.Options{})
	// If there are no errors parsing cache headers and there are no
	// reasons not to cache, then we cache
	if err == nil && len(reasons) == 0 {
		shouldCache = true
		expireTime = resExpireTime
	}

	if doc.Document == nil {
		doc.Document, err = ld.DocumentFromReader(res.Body)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
	}

	// If we went down a branch that marked shouldCache true then lets add the
	// cache entry into the cache
	if shouldCache && d.cacheEngine != nil {
		err = d.cacheEngine.Set(u, doc, expireTime)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
	}

	return doc, nil
}
