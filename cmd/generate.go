package cmd

import (
	"fmt"
	"os"

	transformer "github.com/Abraxas-365/swagGopher/internal/transform"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate [spec-file]",
	Short: "Generate route files from OpenAPI spec",
	Long: `Generate individual JSON route files from an OpenAPI specification file.
The tool will create separate files for each route and auth endpoint.

Example:
  swagGopher generate swagger.yaml
  swagGopher generate swagger.yaml -o custom-routes`,
	Args: cobra.ExactArgs(1),
	RunE: runGenerate,
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringP("output", "o", "routes", "Output directory for generated files")
}

func runGenerate(cmd *cobra.Command, args []string) error {
	outputDir, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Validate input file exists
	if _, err := os.Stat(args[0]); os.IsNotExist(err) {
		return fmt.Errorf("specification file '%s' does not exist", args[0])
	}

	if verbose {
		fmt.Printf("Processing OpenAPI spec: %s\n", args[0])
		fmt.Printf("Output directory: %s\n", outputDir)
	}

	return transformer.GenerateRoutes(args[0], outputDir)
}
