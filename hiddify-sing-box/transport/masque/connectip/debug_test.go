package connectip

import "testing"

func TestConnectIPDebugDisabledInProd(t *testing.T) {
	if ConnectIPDebugEnabled() {
		t.Fatal("ConnectIPDebugEnabled want false in prod")
	}
}
