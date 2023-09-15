package c_polygonid

import (
	"flag"
	"os"
	"testing"

	httpmock "github.com/0xPolygonID/c-polygonid/testing"
)

var catchUnusedHttpresp = flag.Bool("find-unused-httpresp", false,
	"fail if there are unused httpresp_* files")

func TestMain(m *testing.M) {
	retCode := m.Run()
	flag.Parse()

	if *catchUnusedHttpresp {
		if !httpmock.CheckForRedundantHttpresps("testdata", "httpresp_") {
			os.Exit(1)
		}
	}

	os.Exit(retCode)
}
