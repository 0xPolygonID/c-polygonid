package c_polygonid

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPFSCli(t *testing.T) {
	ipfsURL := os.Getenv("IPFS_URL")
	if ipfsURL == "" {
		t.Skip("IPFS_URL is not set")
	}

	f, err := os.ReadFile("testdata/httpresp_kyc-v3.json-ld")
	require.NoError(t, err)

	cli := &ipfsCli{rpcURL: ipfsURL}

	cid, err := cli.Add(context.Background(), bytes.NewReader(f), "xxx")
	require.NoError(t, err)
	require.Equal(t, "QmXwNybNDvsdva11ypERby1nYnR5vJPTy9ZvHdnhaPMD7z", cid)

	fReader, err := cli.Cat(cid)
	require.NoError(t, err)

	defer func() { _ = fReader.Close() }()

	f2, err := io.ReadAll(fReader)
	require.NoError(t, err)
	require.Equal(t, f, f2)
}
