package main

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/Irish-Joseph/diagpermit/internal/config"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check the health of this DiagPermit installation",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()
		section(w, "DiagPermit doctor")
		ok := true
		check := func(name, detail string, good bool) {
			mark := "ok  "
			if !good {
				mark = "warn"
			}
			if !good && name == "request file" {
				mark = "info"
			}
			fmt.Fprintf(w, "  [%s] %-24s %s\n", mark, name, detail)
			if !good && name != "request file" {
				ok = false
			}
		}

		check("version", versionString(), true)
		check("platform", runtime.GOOS+"/"+runtime.GOARCH, runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin")
		check("protocol", "protocol version "+protocol.ProtocolVersion+" supported", true)
		check("telemetry", "OFF (no telemetry in V0.1)", true)

		if _, err := config.Load(config.DefaultFile); err != nil {
			check("request file", "diagpermit.yaml not found or invalid — run `diagpermit init`", false)
		} else {
			check("request file", "diagpermit.yaml valid", true)
		}

		for _, b := range []string{"python3", "python", "node", "java", "go", "docker"} {
			if _, err := exec.LookPath(b); err == nil {
				check("binary: "+b, "found", true)
			}
		}
		fmt.Fprintln(w)
		if ok {
			fmt.Fprintln(w, "DiagPermit is ready.")
		} else {
			fmt.Fprintln(w, "Fix the warnings above, or ignore optional ones (e.g. absent runtimes).")
		}
		return nil
	},
}

func init() { rootCmd.AddCommand(doctorCmd) }
