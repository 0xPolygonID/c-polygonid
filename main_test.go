package c_polygonid

import (
	"flag"
	"os"
	"testing"
)

var catchUnusedHttpresp = flag.Bool("find-unused-httpresp", false,
	"fail if there are unused httpresp_* files")

func TestMain(m *testing.M) {
	retCode := m.Run()
	flag.Parse()

	if *catchUnusedHttpresp {
		if errCode := checkForRedundantHttpresps(); errCode != 0 {
			os.Exit(errCode)
		}
	}

	os.Exit(retCode)
}
