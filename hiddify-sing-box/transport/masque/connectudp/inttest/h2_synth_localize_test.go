package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestLocalizeConnectUDPH2UploadMaxCapsule(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2UploadMaxCapsule(t)
}

func TestLocalizeConnectUDPH2UploadMaxCapsuleDirectDial(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2UploadMaxCapsuleDirectDial(t)
}

func TestLocalizeConnectUDPH2EchoDuplexAsymmetricVsBidi(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2EchoDuplexAsymmetricVsBidi(t)
}

func TestLocalizeConnectUDPH2DownloadPipelineDepth(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2DownloadPipelineDepth(t)
}

func TestLocalizeConnectUDPH2Pipeline1ProdShape(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2Pipeline1ProdShape(t)
}

func TestLocalizeConnectUDPH2EchoPipeline256VsUnlimited(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2EchoPipeline256VsUnlimited(t)
}

func TestLocalizeConnectUDPH2DownloadFountain(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2DownloadFountain(t)
}

func TestLocalizeConnectUDPH2DownloadFountainMaxCapsule(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2DownloadFountainMaxCapsule(t)
}

func TestLocalizeConnectUDPH2DownloadFountainPayloadScaling(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2DownloadFountainPayloadScaling(t)
}

func TestLocalizeConnectUDPH2UploadPayloadScaling(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2UploadPayloadScaling(t)
}

func TestLocalizeConnectUDPH2UploadVsConnectStreamAnchor(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2UploadVsConnectStreamAnchor(t)
}

func TestLocalizeConnectUDPH2UploadVsConnectStreamSameWriteSize(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2UploadVsConnectStreamSameWriteSize(t)
}

func TestLocalizeConnectUDPH2UploadDirectDialVsListenPacket(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2UploadDirectDialVsListenPacket(t)
}

func TestLocalizeConnectUDPH2DownloadFountainDirectDialVsListenPacket(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2DownloadFountainDirectDialVsListenPacket(t)
}

func TestLocalizeConnectUDPH2UploadBulkFlushTLSFlushTax(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2UploadBulkFlushTLSFlushTax(t)
}

func TestLocalizeConnectUDPH2UploadDockerTlsTaxSweep(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2UploadDockerTlsTaxSweep(t)
}
