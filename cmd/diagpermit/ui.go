package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/Irish-Joseph/diagpermit/internal/viewer"
)

var (
	uiTrustStore string
	uiNoOpen     bool
)

var uiCmd = &cobra.Command{
	Use:   "ui [request-or-artifact]",
	Short: "Open the local visual consent and diagnostic viewer",
	Long: `Starts a loopback-only viewer on a random port.

Diagnostic data remains on this computer. DiagPermit does not upload it,
load remote assets, enable CORS, or listen on a network interface.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		input := ""
		if len(args) == 1 {
			input = args[0]
		}
		return viewer.Run(ctx, viewer.Options{
			Input: input, TrustStore: uiTrustStore, NoOpen: uiNoOpen,
			Logger: log.New(cmd.ErrOrStderr(), "viewer: ", log.LstdFlags),
		})
	},
}

func init() {
	uiCmd.Flags().StringVar(&uiTrustStore, "trust-store", "", "local requester trust-store JSON path")
	uiCmd.Flags().BoolVar(&uiNoOpen, "no-open", false, "do not automatically open a browser")
	rootCmd.AddCommand(uiCmd)
}
