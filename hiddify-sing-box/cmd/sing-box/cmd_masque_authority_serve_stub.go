//go:build !with_masque

package main

import (
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var commandMasqueAuthorityServe = &cobra.Command{
	Use:   "masque-authority-serve",
	Short: "MASQUE CONNECT authority HTTP/3 only (requires build tag with_masque)",
	Run: func(cmd *cobra.Command, args []string) {
		log.Fatal("sing-box was built without with_masque; rebuild with -tags with_masque")
	},
}

func init() {
	mainCommand.AddCommand(commandMasqueAuthorityServe)
}
