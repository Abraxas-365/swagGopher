package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "openapi-transformer",
	Short: "Transform OpenAPI specs into custom JSON route files",
	Long: `A CLI tool that transforms OpenAPI/Swagger specifications into 
custom JSON route files for API testing and documentation.

Example usage:
  openapi-transformer generate swagger.yaml
  openapi-transformer generate swagger.yaml --output custom-routes`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Global flags can be added here
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
}
