package c_polygonid

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	retCode := m.Run()

	if errCode := checkForRedundantHttpresps(); errCode != 0 {
		os.Exit(errCode)
	}

	os.Exit(retCode)
}
