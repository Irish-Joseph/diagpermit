package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/diagx/diagx/internal/pipeline"
)

var collectorsCmd = &cobra.Command{
	Use:     "collectors",
	Aliases: []string{"collector"},
	Short:   "List available collectors and their declared capabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()
		section(w, "DiagX collectors (V0.1)")
		fmt.Fprintln(w, "Collectors expose typed capabilities, never arbitrary behaviour.")
		for _, c := range pipeline.AllCollectors() {
			fmt.Fprintf(w, "\n%s (v%s)\n", c.ID(), c.Version())
			for _, cap := range c.Capabilities() {
				fmt.Fprintf(w, "  %-28s %s\n", cap.ID, cap.Description)
				var extras []string
				if cap.Network {
					extras = append(extras, "requires network")
				}
				if cap.Process != "" {
					extras = append(extras, "executes: "+cap.Process)
				}
				if cap.Sensitivity != "" {
					extras = append(extras, "sensitivity: "+cap.Sensitivity)
				}
				if len(extras) > 0 {
					line := ""
					for i, e := range extras {
						if i > 0 {
							line += ", "
						}
						line += e
					}
					fmt.Fprintf(w, "      %s\n", line)
				}
			}
		}
		return nil
	},
}

func init() { rootCmd.AddCommand(collectorsCmd) }
