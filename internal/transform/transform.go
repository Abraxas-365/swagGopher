package transformer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type Spects struct {
	AuthApi *AuthRoute `json:"authApi"`
	Routes  []Route    `json:"routes"`
}

type Response struct {
	Status int         `json:"status"`
	Body   interface{} `json:"body,omitempty"`
}

type AuthRoute struct {
	BaseURL     string             `json:"baseUrl"`
	Path        string             `json:"path"`
	Body        interface{}        `json:"body,omitempty"`
	QueryParams *map[string]string `json:"queryParams,omitempty"`
	Response    Response           `json:"response"`
}

type Route struct {
	BaseURL     string             `json:"baseUrl"`
	Path        string             `json:"path"`
	Method      string             `json:"method"`
	RequireAuth bool               `json:"requireAuth"`
	AuthFile    string             `json:"authFile,omitempty"`
	Body        interface{}        `json:"body,omitempty"`
	QueryParams *map[string]string `json:"queryParams,omitempty"`
	PathParams  *map[string]string `json:"pathParams,omitempty"`
	Response    Response           `json:"response"`
}

// Update the transformOpenAPIToCustomYAML function
func TransformOpenAPIToCustomYAML(specPath string) (*Spects, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		return nil, err
	}

	specs := &Spects{
		Routes: []Route{},
	}

	baseURL := ""
	if len(doc.Servers) > 0 {
		baseURL = doc.Servers[0].URL
	}

	// First pass: find auth endpoint
	var authFilename string
	for path, pathItem := range doc.Paths.Map() {
		for method, operation := range pathItem.Operations() {
			if isAuthEndpoint(path, method, operation) {
				specs.AuthApi = createAuthRoute(baseURL, path, operation)
				authFilename = generateFilename("auth", specs.AuthApi.Path)
				break
			}
		}
		if specs.AuthApi != nil {
			break
		}
	}

	// Second pass: process all other routes
	for path, pathItem := range doc.Paths.Map() {
		for method, operation := range pathItem.Operations() {
			if isAuthEndpoint(path, method, operation) {
				continue
			}

			route := Route{
				BaseURL:     baseURL,
				Path:        path,
				Method:      strings.ToUpper(method),
				RequireAuth: requiresAuth(operation),
				Response: Response{
					Status: 200,
				},
			}

			// Add auth file reference if route requires auth
			if route.RequireAuth && authFilename != "" {
				route.AuthFile = authFilename
			}

			// Handle Path Parameters and Query Parameters
			if operation.Parameters != nil {
				pathParams := make(map[string]string)
				queryParams := make(map[string]string)

				for _, param := range operation.Parameters {
					switch param.Value.In {
					case "path":
						if param.Value.Example != nil {
							pathParams[param.Value.Name] = fmt.Sprint(param.Value.Example)
						} else if param.Value.Schema != nil && param.Value.Schema.Value != nil {
							defaultValue := generateDefaultBody(param.Value.Schema.Value)
							pathParams[param.Value.Name] = fmt.Sprint(defaultValue)
						}
					case "query":
						if param.Value.Example != nil {
							queryParams[param.Value.Name] = fmt.Sprint(param.Value.Example)
						} else if param.Value.Schema != nil && param.Value.Schema.Value != nil {
							defaultValue := generateDefaultBody(param.Value.Schema.Value)
							queryParams[param.Value.Name] = fmt.Sprint(defaultValue)
						}
					}
				}

				if len(pathParams) > 0 {
					route.PathParams = &pathParams
				}
				if len(queryParams) > 0 {
					route.QueryParams = &queryParams
				}
			}

			// Handle Request Body
			if operation.RequestBody != nil && operation.RequestBody.Value != nil {
				for contentType, mediaType := range operation.RequestBody.Value.Content {
					if contentType == "application/json" {
						if mediaType.Example != nil {
							route.Body = mediaType.Example
						} else if mediaType.Schema != nil {
							route.Body = generateDefaultBody(mediaType.Schema.Value)
						}
						break
					}
				}
			}

			// Handle Response
			if operation.Responses != nil {
				for status, respRef := range operation.Responses.Map() {
					statusCode, err := strconv.Atoi(status)
					if err == nil && statusCode >= 200 && statusCode < 300 && respRef.Value != nil {
						route.Response.Status = statusCode
						if respRef.Value.Content != nil {
							if mediaType, ok := respRef.Value.Content["application/json"]; ok {
								if mediaType.Example != nil {
									route.Response.Body = mediaType.Example
								} else if mediaType.Schema != nil {
									route.Response.Body = generateDefaultBody(mediaType.Schema.Value)
								}
							}
						}
						break
					}
				}
			}

			specs.Routes = append(specs.Routes, route)
		}
	}

	return specs, nil
}

func createAuthRoute(baseURL, path string, operation *openapi3.Operation) *AuthRoute {
	authRoute := &AuthRoute{
		BaseURL: baseURL,
		Path:    path,
		Response: Response{
			Status: 200,
		},
	}

	// Handle auth endpoint body and params
	if operation.RequestBody != nil && operation.RequestBody.Value != nil {
		for contentType, mediaType := range operation.RequestBody.Value.Content {
			if contentType == "application/json" {
				if mediaType.Example != nil {
					authRoute.Body = mediaType.Example
				} else if mediaType.Schema != nil {
					authRoute.Body = generateDefaultBody(mediaType.Schema.Value)
				}
				break
			}
		}
	}

	// Handle auth endpoint query params
	if operation.Parameters != nil {
		queryParams := make(map[string]string)
		for _, param := range operation.Parameters {
			if param.Value.In == "query" {
				if param.Value.Example != nil {
					queryParams[param.Value.Name] = fmt.Sprint(param.Value.Example)
				} else if param.Value.Schema != nil && param.Value.Schema.Value != nil {
					defaultValue := generateDefaultBody(param.Value.Schema.Value)
					queryParams[param.Value.Name] = fmt.Sprint(defaultValue)
				}
			}
		}
		if len(queryParams) > 0 {
			authRoute.QueryParams = &queryParams
		}
	}

	// Handle Response
	if operation.Responses != nil {
		for status, respRef := range operation.Responses.Map() {
			statusCode, err := strconv.Atoi(status)
			if err == nil && statusCode >= 200 && statusCode < 300 && respRef.Value != nil {
				authRoute.Response.Status = statusCode
				if respRef.Value.Content != nil {
					if mediaType, ok := respRef.Value.Content["application/json"]; ok {
						if mediaType.Example != nil {
							authRoute.Response.Body = mediaType.Example
						} else if mediaType.Schema != nil {
							authRoute.Response.Body = generateDefaultBody(mediaType.Schema.Value)
						}
					}
				}
				break
			}
		}
	}

	return authRoute
}

func buildFullRoute(baseURL, path string) string {
	// Remove trailing slash from baseURL if exists
	baseURL = strings.TrimRight(baseURL, "/")
	// Ensure path starts with slash
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return baseURL + path
}

func isAuthEndpoint(path, method string, operation *openapi3.Operation) bool {
	authPaths := []string{"/login", "/token", "/auth", "/oauth"}
	for _, authPath := range authPaths {
		if strings.Contains(path, authPath) {
			return true
		}
	}

	if operation.Tags != nil {
		for _, tag := range operation.Tags {
			if strings.Contains(strings.ToLower(tag), "auth") {
				return true
			}
		}
	}

	return false
}

func requiresAuth(operation *openapi3.Operation) bool {
	return operation.Security != nil && len(*operation.Security) > 0
}

func generateDefaultBody(schema *openapi3.Schema) interface{} {
	if schema == nil || schema.Type == nil {
		return nil
	}

	schemaType := ""
	if len(*schema.Type) > 0 {
		schemaType = (*schema.Type)[0]
	}

	switch schemaType {
	case "object":
		body := make(map[string]interface{})
		if schema.Properties != nil {
			for propName, prop := range schema.Properties {
				if prop.Value != nil {
					body[propName] = generateDefaultBody(prop.Value)
				}
			}
		}
		return body
	case "array":
		if schema.Items != nil && schema.Items.Value != nil {
			return []interface{}{generateDefaultBody(schema.Items.Value)}
		}
		return []interface{}{}
	case "string":
		if schema.Example != nil {
			return schema.Example
		}
		return "string"
	case "number":
		if schema.Example != nil {
			return schema.Example
		}
		return 0.0
	case "integer":
		if schema.Example != nil {
			return schema.Example
		}
		return 0
	case "boolean":
		if schema.Example != nil {
			return schema.Example
		}
		return false
	default:
		return nil
	}
}

func getDefaultValueForType(schemaType string) string {
	switch schemaType {
	case "string":
		return "string"
	case "integer":
		return "0"
	case "number":
		return "0.0"
	case "boolean":
		return "false"
	case "array":
		return "[]"
	case "object":
		return "{}"
	default:
		return ""
	}
}

func generateFilename(method, path string) string {
	// Remove leading slash if present
	path = strings.TrimPrefix(path, "/")

	// Split the path into parts
	parts := strings.Split(path, "/")

	// Process each part
	cleanParts := make([]string, 0)
	for _, part := range parts {
		if part != "" {
			// Replace path parameters with 'by' prefix
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				part = "by_" + strings.Trim(part, "{}")
			}
			// Replace dots with underscores
			part = strings.ReplaceAll(part, ".", "_")
			// Replace hyphens with underscores
			part = strings.ReplaceAll(part, "-", "_")
			cleanParts = append(cleanParts, part)
		}
	}

	// Join all parts with underscores
	pathStr := strings.Join(cleanParts, "_")

	// Create filename with method prefix and .json extension
	return fmt.Sprintf("%s_%s.json", strings.ToLower(method), pathStr)
}

func GenerateRoutes(specPath string, outputDir string) error {
	specs, err := TransformOpenAPIToCustomYAML(specPath)
	if err != nil {
		return fmt.Errorf("failed to transform OpenAPI spec: %w", err)
	}

	// Create output directory if it doesn't exist
	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save auth route if it exists
	if specs.AuthApi != nil {
		authJSON, err := json.MarshalIndent(specs.AuthApi, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal auth route: %w", err)
		}

		filename := generateFilename("auth", specs.AuthApi.Path)
		err = os.WriteFile(filepath.Join(outputDir, filename), authJSON, 0644)
		if err != nil {
			return fmt.Errorf("failed to write auth route file: %w", err)
		}
	}

	// Save each route in a separate file
	for _, route := range specs.Routes {
		routeJSON, err := json.MarshalIndent(route, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal route: %w", err)
		}

		filename := generateFilename(route.Method, route.Path)
		err = os.WriteFile(filepath.Join(outputDir, filename), routeJSON, 0644)
		if err != nil {
			return fmt.Errorf("failed to write route file: %w", err)
		}
	}

	fmt.Printf("Route files generated successfully in %s directory!\n", outputDir)
	return nil
}
