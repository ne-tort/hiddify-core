package masque

import "os"

func init() {
	if os.Getenv("HIDDIFY_LOCALIZE_ECHO_GATE") == "1" {
		SetLocalizeEchoGateStrict(true)
	}
}
