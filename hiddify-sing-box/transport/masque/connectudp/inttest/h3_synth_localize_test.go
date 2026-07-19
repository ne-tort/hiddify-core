package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestLocalizeConnectUDPH3DuplexEcho(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3DuplexEcho(t)
}

func TestLocalizeConnectUDPH3DownloadPipelineDepth(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3DownloadPipelineDepth(t)
}

func TestLocalizeConnectUDPH3DownloadFountain(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3DownloadFountain(t)
}

func TestLocalizeConnectUDPH3Pipeline1ProdShape(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3Pipeline1ProdShape(t)
}

func TestLocalizeConnectUDPH3UploadPayloadScaling(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3UploadPayloadScaling(t)
}
