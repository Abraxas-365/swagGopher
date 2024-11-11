# SwagGopher CLI 🐹✨

Welcome to the **swagGopher CLI**! Transform your OpenAPI specs into JSON route files with the elegance of a gopher in sunglasses. Whether you're debugging, documenting, or just showing off, swagGopher has got your back.

## What Does swagGopher Do? 🤔

The swagGopher CLI takes your OpenAPI specification files and magically turns them into individual JSON route files. Perfect for testing, documentation, or just flexing your API muscles.

## Installation 🛠️

First, make sure Go is installed on your machine. Then, clone the repository and install the CLI:

```bash
git clone https://github.com/yourusername/swagGopher.git
cd swagGopher
go build -o swagGopher
```
## Usage 📚

### Generating Route Files

Turn your OpenAPI specs into JSON with a simple command:

```bash
swagGopher generate [spec-file] [flags]
```

### Flags

-     `-o, --output`: Specify the output directory for generated files. Default is `routes/`.

### Example

Transform your API spec like a pro:

```bash
swagGopher generate swagger.yaml -o custom-routes
```

## Testing Your Routes 🧪

Once you've generated your routes, test them with ease:

```bash
swagGopher test [directory] [flags]
```

### Flags

-     `-f, --file`: Specify a specific route file to test.
-     `-p, --path`: Test a route by specifying the HTTP method and path pattern (e.g., `GET /api/users/{id}`).
-     `-t, --token`: Provide a Bearer token for authentication. Bearer is being add by default Bearer {token}
-     `-b, --base-url`: Override the base URL for all requests.
-     `-s, --status-only`: Only compare status codes.
-     `-c, --concise`: Hide detailed body comparison errors.
-     `--table`: Show results in table format instead of JSON.
-     `--curl`: Show equivalent curl commands.

### Examples

#### Test Using a File

Test a specific route using a file:

```bash
swagGopher test routes --file get_users.json --token "abc123" 
#or pipe to fx
swagGopher test routes --file get_users.json --token "abc123" |fx
#or test all
swagGopher test routes 

```

#### Test Using a Path Pattern

Test a route by specifying the HTTP method and path pattern:

```bash
swagGopher test routes --path "GET /api/organizations/{organizationId}/members/" --base-url "https://api.example.com"
```

#### Display Results in Table Format

To display results in a table format:

```bash
swagGopher test routes --path "GET /api/users" --table
```

#### Show Equivalent Curl Command

To display the equivalent curl command for each request:

```bash
swagGopher test routes --file get_users.json --curl
```

## Why Use swagGopher? 🤷‍♂️

-     **Time Saver**: Automagically converts your OpenAPI specs into testable JSON files.
-     **Organized**: Neatly stores each route in its own file for easy management.
-     **Stylish**: Because running a CLI tool with a name like swagGopher makes you the coolest dev in the room.

## Contributing 🤝

Want to make swagGopher even swaggier? Fork the repo, make your changes, and submit a pull request. We welcome all contributions, whether they're bug fixes, new features, or just fun ideas!

## License 📜

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer 🚨

This tool won't actually give you superpowers, but it might make you feel like you have them. Use responsibly!

---

Happy transforming with swagGopher! 🌟
