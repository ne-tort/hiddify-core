package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestWireguard(t *testing.T) {
	url := "wg://server:222/?pk=[private_key]&local_address=10.0.0.2/24&peer_public_key=[peer_public_key]&pre_shared_key=[pre_shared_key]&workers=2&mtu=1408&reserved=0,0,0"

	expectedJSON := `
	{
		"endpoints": [
		  {
			"type": "wireguard",
			"tag": "wireguard § 0",
			"address": ["10.0.0.2/24"],
			"private_key": "[private_key]",
			"mtu": 1408,
			"workers": 2,
			"peers": [
			  {
				"address": "server",
				"port": 222,
				"public_key": "[peer_public_key]",
				"pre_shared_key": "[pre_shared_key]",
				"allowed_ips": ["0.0.0.0/0", "::/0"],
				"reserved": [0, 0, 0]
			  }
			]
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
