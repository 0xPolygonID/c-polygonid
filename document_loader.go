package c_polygonid

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
	shell "github.com/ipfs/go-ipfs-api"
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

type cachedRemoteDocument struct {
	RemoteDocument *ld.RemoteDocument
	ExpireTime     time.Time
}

type documentLoader struct {
	ipfsCli *shell.Shell
	ipfsGW  string
}

func newDocumentLoader(ipfsCli *shell.Shell, ipfsGW string) *documentLoader {
	return &documentLoader{
		ipfsCli: ipfsCli,
		ipfsGW:  ipfsGW,
	}
}

func (d *documentLoader) LoadDocument(
	u string) (doc *ld.RemoteDocument, err error) {

	db, closeDB, err := getCacheDB()
	if err != nil {
		db = nil
	} else {
		defer closeDB()
	}

	const ipfsPrefix = "ipfs://"

	switch {
	case strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://"):
		return d.loadDocumentFromHTTP(db, u)

	case strings.HasPrefix(u, ipfsPrefix):
		// supported URLs:
		// ipfs://<cid>/dir/schema.json
		// ipfs://<cid>

		if db != nil {
			var cachedDoc cachedRemoteDocument
			cachedDoc, err = getRemoteDocumentFromCache(db, []byte(u))
			if errors.Is(err, badger.ErrKeyNotFound) {
				// pass
			} else if err != nil {
				slog.Error("error getting remote document from cache",
					"err", err)
			} else {
				return cachedDoc.RemoteDocument, nil
			}
		}

		doc = &ld.RemoteDocument{DocumentURL: u}

		// strip ipfs:// prefix
		u = u[len(ipfsPrefix):]

		switch {
		case d.ipfsCli != nil:
			doc.Document, err = d.loadDocumentFromIPFSNode(u)
		case d.ipfsGW != "":
			doc.Document, err = d.loadDocumentFromIPFSGW(db, u)
		default:
			err = ld.NewJsonLdError(ld.LoadingDocumentFailed,
				errors.New("ipfs is not configured"))
		}
		if err != nil {
			return nil, err
		}

		if db != nil {
			err = putRemoteDocumentToCache(db, []byte(doc.DocumentURL),
				cachedRemoteDocument{RemoteDocument: doc})
			if err != nil {
				slog.Error("error putting remote document to cache",
					"err", err)
			}
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

func (d *documentLoader) loadDocumentFromIPFSGW(db *badger.DB,
	ipfsURL string) (any, error) {

	ipfsURL = strings.TrimRight(d.ipfsGW, "/") + "/ipfs/" +
		strings.TrimLeft(ipfsURL, "/")
	doc, err := d.loadDocumentFromHTTP(db, ipfsURL)
	if err != nil {
		return nil, err
	}
	return doc.Document, nil
}

func (d *documentLoader) loadDocumentFromHTTP(db *badger.DB,
	u string) (*ld.RemoteDocument, error) {

	var cachedDoc cachedRemoteDocument
	var cacheFound bool
	var err error

	if db != nil {
		cachedDoc, err = getRemoteDocumentFromCache(db, []byte(u))
		if errors.Is(err, badger.ErrKeyNotFound) {
			cacheFound = false
		} else if err != nil {
			slog.Error("error getting remote document from cache",
				"err", err)
			cacheFound = false
		} else {
			cacheFound = true
		}
	}

	now := time.Now()

	// First we check if we hit in the cache, and the cache entry is valid
	// We need to check if ExpireTime >= now, so we negate the comparison below
	if cacheFound && cachedDoc.ExpireTime.After(now) {
		return cachedDoc.RemoteDocument, nil
	}

	remoteDoc := &ld.RemoteDocument{}

	// We use shouldCache, and expireTime at the end of this method to create
	// an object to store in the cache. Set them to sane default values now
	shouldCache := false
	expireTime := time.Now()

	req, err := http.NewRequest("GET", u, http.NoBody)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
	}
	// We prefer application/ld+json, but fallback to application/json
	// or whatever is available
	req.Header.Add("Accept", acceptHeader)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed,
			fmt.Sprintf("Bad response status code: %d",
				res.StatusCode))
	}

	remoteDoc.DocumentURL = res.Request.URL.String()

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
				remoteDoc.ContextURL = contextLink[0]["target"]
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
			remoteDoc, err = d.LoadDocument(finalURL)
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

	if remoteDoc.Document == nil {
		remoteDoc.Document, err = ld.DocumentFromReader(res.Body)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
	}

	// If we went down a branch that marked shouldCache true then lets add the
	// cache entry into the cache
	if shouldCache && db != nil {
		cachedDoc.RemoteDocument = remoteDoc
		cachedDoc.ExpireTime = expireTime
		err = putRemoteDocumentToCache(db, []byte(u), cachedDoc)
		if err != nil {
			slog.Error("error putting remote document to cache",
				"err", err)
		}
	}

	return remoteDoc, nil
}
