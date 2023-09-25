package c_polygonid

import (
	"flag"
	"log/slog"
	"os"
	"testing"

	httpmock "github.com/0xPolygonID/c-polygonid/testing"
)

var catchUnusedHttpresp = flag.Bool("find-unused-httpresp", false,
	"fail if there are unused httpresp_* files")

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource:   true,
		Level:       slog.LevelDebug,
		ReplaceAttr: nil,
	})))

	retCode := m.Run()
	flag.Parse()

	if *catchUnusedHttpresp {
		if !httpmock.CheckForRedundantHttpresps("testdata", "httpresp_") {
			os.Exit(1)
		}
	}

	os.Exit(retCode)
}
