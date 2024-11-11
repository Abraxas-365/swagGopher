package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	transformer "github.com/Abraxas-365/swagGopher/internal/transform"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var (
	testFile    string
	authFile    string
	authToken   string
	baseURL     string
	statusOnly  bool
	concise     bool
	tableFormat bool
	showCurl    bool
	pathPattern string
)

var testCmd = &cobra.Command{
	Use:   "test [directory]",
	Short: "Test API routes",
	Long: `Test API routes from generated JSON files. You can test a single file
or an entire directory of route files.

Example:
  swagGopher test routes/
  swagGopher test routes/ --file get_users.json
  swagGopher test routes/ --token "Bearer xyz123"
  swagGopher test routes/ --base-url "https://api.example.com"`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTests,
}

func runTests(cmd *cobra.Command, args []string) error {
	routesDir := "routes"
	if len(args) > 0 {
		routesDir = args[0]
	}

	// Verify directory exists
	if _, err := os.Stat(routesDir); os.IsNotExist(err) {
		return fmt.Errorf("directory '%s' does not exist", routesDir)
	}

	// Handle path pattern if provided
	if pathPattern != "" {
		foundFile, err := findFileByPath(routesDir, pathPattern)
		if err != nil {
			return err
		}
		testFile = foundFile
	}

	// Rest of your existing validation...

	parser := NewParser(routesDir)
	if err := parser.ParseAndExecute(); err != nil {
		return fmt.Errorf("test execution failed: %w", err)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.Flags().StringVarP(&testFile, "file", "f", "", "Specific route file to test")
	testCmd.Flags().StringVarP(&authFile, "auth-file", "a", "", "Custom auth file to use")
	testCmd.Flags().StringVarP(&authToken, "token", "t", "", "Bearer token for authentication")
	testCmd.Flags().StringVarP(&baseURL, "base-url", "b", "", "Override base URL for all requests")
	testCmd.Flags().BoolVarP(&statusOnly, "status-only", "s", false, "Only compare status codes")
	testCmd.Flags().BoolVarP(&concise, "concise", "c", false, "Hide detailed body comparison errors")
	testCmd.Flags().BoolVarP(&tableFormat, "table", "", false, "Show results in table format instead of JSON")
	testCmd.Flags().BoolVarP(&showCurl, "curl", "", false, "Show equivalent curl commands")
	testCmd.Flags().StringVarP(&pathPattern, "path", "p", "", "Test route by method and path pattern (e.g., 'GET /api/users/{id}')")
	testCmd.MarkFlagsMutuallyExclusive("file", "path") // Can't use both file and path flags
}

type TokenCache struct {
	sync.RWMutex
	tokens map[string]TokenInfo
}
type TestResults struct {
	TotalTests int          `json:"totalTests"`
	Passed     int          `json:"passed"`
	Failed     int          `json:"failed"`
	Results    []TestResult `json:"results"`
}

type TokenInfo struct {
	Token     string
	ExpiresAt time.Time
}

type Parser struct {
	client     *http.Client
	tokenCache *TokenCache
	routesDir  string
}

type BodyComparisonResult struct {
	Matches     bool            `json:"matches"`
	Expected    interface{}     `json:"expected,omitempty"`
	Actual      interface{}     `json:"actual,omitempty"`
	Differences map[string]Diff `json:"differences,omitempty"`
}

type Diff struct {
	Expected interface{} `json:"expected"`
	Actual   interface{} `json:"actual"`
}

type TestResult struct {
	File           string                `json:"file"`
	Method         string                `json:"method"`
	Route          string                `json:"route"`
	ExpectedStatus int                   `json:"expectedStatus"`
	ActualStatus   int                   `json:"actualStatus"`
	BodyComparison *BodyComparisonResult `json:"bodyComparison,omitempty"`
	Error          string                `json:"error,omitempty"`
}

func NewParser(routesDir string) *Parser {
	return &Parser{
		client: &http.Client{
			Timeout: time.Second * 30,
		},
		tokenCache: &TokenCache{
			tokens: make(map[string]TokenInfo),
		},
		routesDir: routesDir,
	}
}

func (p *Parser) ParseAndExecute() error {
	var files []string

	if testFile != "" {
		files = append(files, testFile)
	} else {
		entries, err := os.ReadDir(p.routesDir)
		if err != nil {
			return fmt.Errorf("error reading routes directory: %w", err)
		}

		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				if !strings.HasPrefix(entry.Name(), "auth_") || entry.Name() == authFile {
					files = append(files, entry.Name())
				}
			}
		}
	}

	results := make([]TestResult, 0)
	for _, file := range files {
		result := p.processRoute(file)
		results = append(results, result)
	}

	// Calculate summary
	testResults := TestResults{
		TotalTests: len(results),
		Results:    results,
	}

	for _, result := range results {
		if result.Error == "" &&
			result.ExpectedStatus == result.ActualStatus &&
			(statusOnly || (result.BodyComparison != nil && result.BodyComparison.Matches)) {
			testResults.Passed++
		} else {
			testResults.Failed++
		}
	}

	// Output results based on format
	if tableFormat {
		p.printResults(results)
	} else {
		return p.printJSON(testResults)
	}

	return nil
}

func (p *Parser) printJSON(results TestResults) error {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling results to JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func (p *Parser) processRoute(filename string) TestResult {
	result := TestResult{
		File: filename,
	}

	data, err := os.ReadFile(filepath.Join(p.routesDir, filename))
	if err != nil {
		result.Error = fmt.Sprintf("error reading file: %v", err)
		return result
	}

	var route transformer.Route
	if err := json.Unmarshal(data, &route); err != nil {
		result.Error = fmt.Sprintf("error parsing JSON: %v", err)
		return result
	}

	result.Method = route.Method
	result.ExpectedStatus = route.Response.Status // Set this immediately after unmarshaling

	// Use provided baseURL if available, otherwise use route's baseURL
	routeBaseURL := route.BaseURL
	if baseURL != "" {
		routeBaseURL = baseURL
	}
	result.Route = buildFullRoute(routeBaseURL, route.Path)

	// Handle authentication
	var token string
	if route.RequireAuth || authToken != "" {
		if authToken != "" {
			// Use provided CLI token if available
			token = authToken
			if !strings.HasPrefix(strings.ToLower(token), "bearer ") {
				token = "Bearer " + token
			}
		} else {
			// Fall back to auth file
			authFileToUse := route.AuthFile
			if authFile != "" {
				// Override with CLI provided auth file if specified
				authFileToUse = authFile
			}

			if authFileToUse == "" {
				result.Error = "route requires authentication but no auth file or token provided"
				return result
			}

			var err error
			token, err = p.getToken(authFileToUse)
			token = "Bearer " + token
			if err != nil {
				result.Error = fmt.Sprintf("auth error: %v", err)
				return result
			}
		}
	}

	resp, err := p.makeRequest(&route, token, routeBaseURL)
	if err != nil {
		result.Error = fmt.Sprintf("request error: %v", err)
		result.ActualStatus = 0 // Set to 0 only when there's an error
		return result
	}

	result.ActualStatus = resp.StatusCode

	if !statusOnly && route.Response.Body != nil {
		comparison, err := p.compareResponses(route.Response.Body, resp)
		if err != nil {
			result.Error = fmt.Sprintf("body comparison error: %v", err)
		} else {
			result.BodyComparison = comparison
		}
	}

	return result
}

func (p *Parser) getToken(authFile string) (string, error) {
	p.tokenCache.RLock()
	if tokenInfo, exists := p.tokenCache.tokens[authFile]; exists {
		if time.Now().Before(tokenInfo.ExpiresAt) {
			p.tokenCache.RUnlock()
			return tokenInfo.Token, nil
		}
	}
	p.tokenCache.RUnlock()

	data, err := os.ReadFile(filepath.Join(p.routesDir, authFile))
	if err != nil {
		return "", fmt.Errorf("error reading auth file: %w", err)
	}

	var authRoute transformer.AuthRoute
	if err := json.Unmarshal(data, &authRoute); err != nil {
		return "", fmt.Errorf("error parsing auth JSON: %w", err)
	}

	fullURL := buildFullRoute(authRoute.BaseURL, authRoute.Path)
	body, err := json.Marshal(authRoute.Body)
	if err != nil {
		return "", fmt.Errorf("error marshaling auth body: %w", err)
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("error creating auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making auth request: %w", err)
	}
	defer resp.Body.Close()

	var authResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return "", fmt.Errorf("error decoding auth response: %w", err)
	}

	token, ok := authResponse["token"].(string)
	if !ok {
		return "", fmt.Errorf("token not found in auth response")
	}

	p.tokenCache.Lock()
	p.tokenCache.tokens[authFile] = TokenInfo{
		Token:     token,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	p.tokenCache.Unlock()

	return token, nil
}

func (p *Parser) makeRequest(route *transformer.Route, token string, routeBaseURL string) (*http.Response, error) {
	url := buildFullRoute(routeBaseURL, route.Path)

	if route.PathParams != nil {
		for key, value := range *route.PathParams {
			url = strings.ReplaceAll(url, "{"+key+"}", value)
		}
	}

	if route.QueryParams != nil {
		query := make([]string, 0)
		for key, value := range *route.QueryParams {
			query = append(query, fmt.Sprintf("%s=%s", key, value))
		}
		if len(query) > 0 {
			url += "?" + strings.Join(query, "&")
		}
	}

	var reqBody []byte
	var err error

	if route.Body != nil {
		reqBody, err = json.Marshal(route.Body)
		if err != nil {
			return nil, fmt.Errorf("error marshaling request body: %w", err)
		}
	}

	req, err := http.NewRequest(route.Method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		token = strings.TrimSpace(token)
		if !strings.HasPrefix(strings.ToLower(token), "bearer ") {
			token = "Bearer " + token
		}
		req.Header.Set("Authorization", strings.TrimSpace(token))
	}

	// Show curl command if flag is set
	if showCurl {
		fmt.Printf("\nCurl command for %s:\n%s\n\n", route.Path,
			generateCurlCommand(route.Method, url, req.Header, reqBody))
	}

	return p.client.Do(req)
}

func buildFullRoute(baseURL, path string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return baseURL + path
}

func (p *Parser) compareResponses(expected interface{}, actual *http.Response) (*BodyComparisonResult, error) {
	body, err := io.ReadAll(actual.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var actualBody interface{}
	if err := json.Unmarshal(body, &actualBody); err != nil {
		return nil, fmt.Errorf("error parsing response body: %v", err)
	}

	result := &BodyComparisonResult{
		Expected:    expected,
		Actual:      actualBody,
		Differences: make(map[string]Diff),
	}

	// Compare the bodies and collect differences
	result.Matches = compareValues("", expected, actualBody, result.Differences)

	return result, nil
}
func compareValues(path string, expected, actual interface{}, differences map[string]Diff) bool {
	if expected == nil && actual == nil {
		return true
	}

	if expected == nil || actual == nil {
		differences[path] = Diff{Expected: expected, Actual: actual}
		return false
	}

	switch expectedValue := expected.(type) {
	case map[string]interface{}:
		actualMap, ok := actual.(map[string]interface{})
		if !ok {
			differences[path] = Diff{Expected: expected, Actual: actual}
			return false
		}
		return compareObjects(path, expectedValue, actualMap, differences)

	case []interface{}:
		actualArray, ok := actual.([]interface{})
		if !ok {
			differences[path] = Diff{Expected: expected, Actual: actual}
			return false
		}
		return compareArrays(path, expectedValue, actualArray, differences)

	default:
		if expected != actual {
			differences[path] = Diff{Expected: expected, Actual: actual}
			return false
		}
	}

	return true
}

func compareObjects(path string, expected, actual map[string]interface{}, differences map[string]Diff) bool {
	matches := true
	for key, expectedValue := range expected {
		newPath := key
		if path != "" {
			newPath = path + "." + key
		}

		actualValue, exists := actual[key]
		if !exists {
			differences[newPath] = Diff{Expected: expectedValue, Actual: nil}
			matches = false
			continue
		}

		if !compareValues(newPath, expectedValue, actualValue, differences) {
			matches = false
		}
	}

	// Check for extra fields in actual that aren't in expected
	for key, actualValue := range actual {
		if _, exists := expected[key]; !exists {
			newPath := key
			if path != "" {
				newPath = path + "." + key
			}
			differences[newPath] = Diff{Expected: nil, Actual: actualValue}
			matches = false
		}
	}

	return matches
}

func compareArrays(path string, expected, actual []interface{}, differences map[string]Diff) bool {
	if len(expected) != len(actual) {
		differences[path] = Diff{Expected: expected, Actual: actual}
		return false
	}

	matches := true
	for i := range expected {
		newPath := fmt.Sprintf("%s[%d]", path, i)
		if !compareValues(newPath, expected[i], actual[i], differences) {
			matches = false
		}
	}

	return matches
}

func (p *Parser) printResults(results []TestResult) {
	table := tablewriter.NewWriter(os.Stdout)
	headers := []string{"File", "Method", "Route", "Expected Status", "Actual Status"}
	if !statusOnly {
		headers = append(headers, "Body Match")
	}
	headers = append(headers, "Error/Differences")

	table.SetHeader(headers)
	table.SetAutoWrapText(false)
	table.SetRowLine(true)

	for _, result := range results {
		expectedStatus := fmt.Sprintf("%d", result.ExpectedStatus)
		actualStatus := fmt.Sprintf("%d", result.ActualStatus)

		if result.Error == "" {
			if result.ExpectedStatus == result.ActualStatus {
				actualStatus = "✅ " + actualStatus
			} else {
				actualStatus = "❌ " + actualStatus
			}
		}

		differences := ""
		if result.Error != "" {
			differences = result.Error
		} else if result.BodyComparison != nil && !result.BodyComparison.Matches {
			diffStrings := make([]string, 0)
			for path, diff := range result.BodyComparison.Differences {
				diffStrings = append(diffStrings, fmt.Sprintf(
					"%s: expected '%v', got '%v'",
					path,
					diff.Expected,
					diff.Actual,
				))
			}
			differences = strings.Join(diffStrings, "\n")
		}

		row := []string{
			result.File,
			result.Method,
			result.Route,
			expectedStatus,
			actualStatus,
		}

		if !statusOnly {
			bodyMatch := "✅"
			if result.BodyComparison != nil && !result.BodyComparison.Matches {
				bodyMatch = "❌"
			}
			row = append(row, bodyMatch)
		}

		row = append(row, differences)
		table.Append(row)
	}

	table.Render()
}

func generateCurlCommand(method, url string, headers http.Header, body []byte) string {
	var curl strings.Builder
	curl.WriteString(fmt.Sprintf("curl -X %s \"%s\"", method, url))

	// Add headers
	for key, values := range headers {
		for _, value := range values {
			curl.WriteString(fmt.Sprintf(" \\\n  -H '%s: %s'", key, value))
		}
	}

	// Add body if present
	if len(body) > 0 {
		// Pretty print JSON if possible
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, body, "  ", "  "); err == nil {
			curl.WriteString(fmt.Sprintf(" \\\n  -d '%s'", prettyJSON.String()))
		} else {
			curl.WriteString(fmt.Sprintf(" \\\n  -d '%s'", string(body)))
		}
	}

	return curl.String()
}

func findFileByPath(routesDir, pathPattern string) (string, error) {
	if pathPattern == "" {
		return "", fmt.Errorf("path pattern is required")
	}

	// Split pattern into method and path
	parts := strings.SplitN(pathPattern, " ", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid path pattern format. Expected 'METHOD /path', got '%s'", pathPattern)
	}

	method := strings.ToUpper(strings.TrimSpace(parts[0]))
	path := strings.TrimSpace(parts[1])

	// Read all files in the directory
	entries, err := os.ReadDir(routesDir)
	if err != nil {
		return "", fmt.Errorf("error reading routes directory: %w", err)
	}

	// Look for matching route file
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(routesDir, entry.Name()))
		if err != nil {
			continue
		}

		var route transformer.Route
		if err := json.Unmarshal(data, &route); err != nil {
			continue
		}

		// Check if method and path match
		if strings.EqualFold(route.Method, method) && normalizePath(route.Path) == normalizePath(path) {
			return entry.Name(), nil
		}
	}

	return "", fmt.Errorf("no matching route file found for %s", pathPattern)
}

func normalizePath(path string) string {
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// Remove trailing slash if present
	return strings.TrimRight(path, "/")
}
