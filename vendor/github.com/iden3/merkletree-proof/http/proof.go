package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/merkletree-proof"
)

func init() {
	hashOneP, err := merkletree.NewHashFromBigInt(big.NewInt(1))
	if err != nil {
		panic(err)
	}
	copy(hashOne[:], hashOneP[:])
}

var hashOne merkletree.Hash

var ErrNodeNotFound = errors.New("node not found")

type ReverseHashCli struct {
	URL         string
	HTTPTimeout time.Duration
}

// GenerateProof generates proof of existence or in-existence of a key in
// a tree identified by a treeRoot.
func (cli *ReverseHashCli) GenerateProof(ctx context.Context,
	treeRoot *merkletree.Hash,
	key *merkletree.Hash) (*merkletree.Proof, error) {

	if cli.URL == "" {
		return nil, errors.New("HTTP reverse hash service url is not specified")
	}

	return merkletree_proof.GenerateProof(ctx, cli, treeRoot, key)
}

func (cli *ReverseHashCli) nodeURL(node *merkletree.Hash) string {
	nodeURL := cli.baseURL() + "/node"
	if node == nil {
		return nodeURL
	}
	return nodeURL + "/" + node.Hex()
}

func (cli *ReverseHashCli) baseURL() string {
	return strings.TrimSuffix(cli.URL, "/")
}

func (cli *ReverseHashCli) getHttpTimeout() time.Duration {
	if cli.HTTPTimeout == 0 {
		return 10 * time.Second
	}
	return cli.HTTPTimeout
}

func (cli *ReverseHashCli) GetNode(ctx context.Context,
	hash *merkletree.Hash) (merkletree_proof.Node, error) {

	if hash == nil {
		return merkletree_proof.Node{}, errors.New("hash is nil")
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cli.getHttpTimeout())
		defer cancel()
	}

	httpReq, err := http.NewRequestWithContext(
		ctx, http.MethodGet, cli.nodeURL(hash), http.NoBody)
	if err != nil {
		return merkletree_proof.Node{}, err
	}

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return merkletree_proof.Node{}, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode == http.StatusNotFound {
		var resp map[string]interface{}
		dec := json.NewDecoder(httpResp.Body)
		err := dec.Decode(&resp)
		if err != nil {
			return merkletree_proof.Node{}, err
		}
		if resp["status"] == "not found" {
			return merkletree_proof.Node{}, ErrNodeNotFound
		} else {
			return merkletree_proof.Node{},
				errors.New("unexpected response")
		}
	} else if httpResp.StatusCode != http.StatusOK {
		return merkletree_proof.Node{}, fmt.Errorf(
			"unexpected response: %v", httpResp.StatusCode)
	}

	var nodeResp nodeResponse
	dec := json.NewDecoder(httpResp.Body)
	err = dec.Decode(&nodeResp)
	if err != nil {
		return merkletree_proof.Node{}, err
	}

	return nodeResp.Node, nil
}

func (cli *ReverseHashCli) SaveNodes(ctx context.Context,
	nodes []merkletree_proof.Node) error {

	reqBytes, err := json.Marshal(nodes)
	if err != nil {
		return err
	}

	// if no timeout set on context, set it here
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cli.getHttpTimeout())
		defer cancel()
	}

	bodyReader := bytes.NewReader(reqBytes)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cli.nodeURL(nil), bodyReader)
	if err != nil {
		return err
	}

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", httpResp.StatusCode)
	}

	dec := json.NewDecoder(httpResp.Body)
	var respM map[string]interface{}
	err = dec.Decode(&respM)
	if err != nil {
		return fmt.Errorf("unable to decode RHS response: %w", err)
	}

	if respM["status"] != "OK" {
		return fmt.Errorf("unexpected RHS response status: %s", respM["status"])
	}

	return nil
}

type nodeResponse struct {
	Node   merkletree_proof.Node `json:"node"`
	Status string                `json:"status"`
}
