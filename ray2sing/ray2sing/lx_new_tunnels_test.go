package ray2sing

import "testing"

func TestShadowQUICSingbox(t *testing.T) {
	out, err := ShadowQUICSingbox("shadowquic://user:pass@sq.example.com:443/?sni=www.example.com&alpn=h3#sq")
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "shadowquic" {
		t.Fatalf("type=%s", out.Type)
	}
	if out.Tag != "sq" {
		t.Fatalf("tag=%s", out.Tag)
	}
}

func TestSudokuSingbox(t *testing.T) {
	out, err := SudokuSingbox("sudoku://27efbf96-8f28-4090-8bc8-d35a379d76ee@su.example.com:18443/?aead_method=chacha20-poly1305&table_type=prefer_ascii#su")
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "sudoku" {
		t.Fatalf("type=%s", out.Type)
	}
}

func TestTrustTunnelSingbox(t *testing.T) {
	out, err := TrustTunnelSingbox("trusttunnel://user:pass@vpn.example.com:443/?hostname=vpn.example.com&protocol=http2&insecure=1#tt")
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "trusttunnel" {
		t.Fatalf("type=%s", out.Type)
	}
}

func TestAnyTLSSingbox(t *testing.T) {
	out, err := AnyTLSSingbox("anytls://secret@at.example.com:443/?sni=at.example.com&alpn=h2,http/1.1&fp=chrome#at")
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "anytls" {
		t.Fatalf("type=%s", out.Type)
	}
	if out.Tag != "at" {
		t.Fatalf("tag=%s", out.Tag)
	}
}

func TestShadowTLSSingbox(t *testing.T) {
	out, err := ShadowTLSSingbox("shadowtls://secret@st.example.com:443/?version=3&sni=www.example.com&fp=chrome#st")
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "shadowtls" {
		t.Fatalf("type=%s", out.Type)
	}
}

func TestSnellSingbox(t *testing.T) {
	out, err := SnellSingbox("snell://psk@sn.example.com:440/?version=4&userkey=uk&obfs=http&obfs-host=example.com#sn")
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "snell" {
		t.Fatalf("type=%s", out.Type)
	}
}
