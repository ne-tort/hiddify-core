package h2

// ConnectUDPDialPolicy holds H2 CONNECT-UDP dial shape knobs (W-UDP-4 PR0).
type ConnectUDPDialPolicy struct {
	AsymmetricDuplex bool
	UploadStreams    int
}

// ConnectUDPDialPolicyFromEnv returns prod CONNECT-UDP dial policy (hardcoded; no env).
func ConnectUDPDialPolicyFromEnv() ConnectUDPDialPolicy {
	return ConnectUDPDialPolicy{
		AsymmetricDuplex: true,
		UploadStreams:    1,
	}
}
