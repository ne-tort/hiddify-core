package masquetls

// ApplyServerTCPCollateralALPN sets NextProtos on a cloned TCP collateral TLS config
// without blind overwrite when ALPN already contains h2.
func ApplyServerTCPCollateralALPN(existing []string) ([]string, error) {
	return ApplyH2ServerTCPNextProtos(existing)
}
