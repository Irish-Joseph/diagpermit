package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Irish-Joseph/diagpermit/internal/config"
	"github.com/Irish-Joseph/diagpermit/internal/requestauth"
)

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Create and verify authenticated diagnostic requests",
}

var requestKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 requester key pair and trust-store template",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if requestPrivateKey == "" || requestTrustStore == "" {
			return fmt.Errorf("--private-key and --trust-store are required")
		}
		if err := requireNewFile(requestPrivateKey); err != nil {
			return err
		}
		if err := requireNewFile(requestTrustStore); err != nil {
			return err
		}
		pub, priv, err := requestauth.GenerateKey()
		if err != nil {
			return err
		}
		privatePEM, err := requestauth.MarshalPrivateKey(priv)
		if err != nil {
			return err
		}
		store := requestauth.TrustStore{Keys: []requestauth.TrustKey{{
			KeyID: requestKeyID, Identity: requestIdentity,
			PublicKey:         base64.StdEncoding.EncodeToString(pub),
			TrustedRequesters: []string{requestRequester},
		}}}
		storeJSON, err := json.MarshalIndent(store, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(requestPrivateKey, privatePEM, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(requestTrustStore, append(storeJSON, '\n'), 0o600); err != nil {
			_ = os.Remove(requestPrivateKey)
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Private key: %s\nTrust store: %s\nKeep the private key secret; distribute only the trust-store entry.\n", requestPrivateKey, requestTrustStore)
		return nil
	},
}

var requestSignCmd = &cobra.Command{
	Use:   "sign <request.yaml> <request.dsse.json>",
	Short: "Sign a request using a standard DSSE envelope",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		req, err := config.Load(args[0])
		if err != nil {
			return err
		}
		// #nosec G304 -- key path is explicitly provided by the local user.
		keyData, err := os.ReadFile(requestPrivateKey)
		if err != nil {
			return err
		}
		key, err := requestauth.ParsePrivateKey(keyData)
		if err != nil {
			return err
		}
		envelope, err := requestauth.Sign(req, requestKeyID, key)
		if err != nil {
			return err
		}
		if err := requireNewFile(args[1]); err != nil {
			return err
		}
		if err := os.WriteFile(args[1], append(envelope, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Signed request written to %s\n", args[1])
		return nil
	},
}

var requestVerifyCmd = &cobra.Command{
	Use:   "verify <request-or-envelope>",
	Short: "Verify request signature and local requester trust",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// #nosec G304 -- document path is explicitly provided by the local user.
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var store *requestauth.TrustStore
		if requestTrustStore != "" {
			store, err = requestauth.LoadTrustStore(requestTrustStore)
			if err != nil {
				return err
			}
		}
		result := requestauth.Verify(data, store)
		fmt.Fprintln(cmd.OutOrStdout(), result.Label)
		fmt.Fprintln(cmd.OutOrStdout(), result.Detail)
		if result.Status == requestauth.StatusInvalid {
			return fmt.Errorf("request authentication failed")
		}
		return nil
	},
}

var (
	requestPrivateKey string
	requestTrustStore string
	requestKeyID      string
	requestIdentity   string
	requestRequester  string
)

func requireNewFile(path string) error {
	if path == "" {
		return fmt.Errorf("output path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err == nil {
		return fmt.Errorf("refusing to overwrite existing file %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func init() {
	requestKeygenCmd.Flags().StringVar(&requestPrivateKey, "private-key", "", "new private key PEM path")
	requestKeygenCmd.Flags().StringVar(&requestTrustStore, "trust-store", "", "new trust-store JSON path")
	requestKeygenCmd.Flags().StringVar(&requestKeyID, "key-id", "requester-key-1", "stable key identifier")
	requestKeygenCmd.Flags().StringVar(&requestIdentity, "identity", "", "human-readable signer identity (required)")
	requestKeygenCmd.Flags().StringVar(&requestRequester, "requester", "", "requester name trusted for this key (required)")
	_ = requestKeygenCmd.MarkFlagRequired("identity")
	_ = requestKeygenCmd.MarkFlagRequired("requester")
	requestSignCmd.Flags().StringVar(&requestPrivateKey, "private-key", "", "private key PEM path (required)")
	_ = requestSignCmd.MarkFlagRequired("private-key")
	requestSignCmd.Flags().StringVar(&requestKeyID, "key-id", "requester-key-1", "key identifier recorded in the envelope")
	requestVerifyCmd.Flags().StringVar(&requestTrustStore, "trust-store", "", "local trust-store JSON path")
	requestCmd.AddCommand(requestKeygenCmd, requestSignCmd, requestVerifyCmd)
	rootCmd.AddCommand(requestCmd)
}
