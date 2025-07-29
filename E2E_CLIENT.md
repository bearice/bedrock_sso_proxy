# Bedrock SSO Proxy E2E Test Client

A command-line client for end-to-end testing of the Bedrock SSO Proxy server with support for both proxy and direct API connections.

## Setup

1. **Configure the proxy server**: Create a `config.yaml` file with your AWS credentials and JWT secret:

```yaml
server:
  host: "0.0.0.0"
  port: 3000

jwt:
  secret: "your-jwt-secret-here"

aws:
  region: "us-east-1"
  access_key_id: "your-aws-access-key"
  secret_access_key: "your-aws-secret-key"

logging:
  level: "info"
```

2. **Start the proxy server**:
```bash
cargo run --bin bedrock_proxy
```

3. **Build the e2e client**:
```bash
cargo build --example e2e_client
```

## Usage

### Health Check
Test if the proxy server is running:
```bash
cargo run --example e2e_client -- health
```

### Send Single Message
Send a single message to a model:
```bash
# Standard response through proxy
cargo run --example e2e_client -- message --text "Hello, how are you?"

# Streaming response
cargo run --example e2e_client -- message --text "Hello, how are you?" --streaming

# Different model
cargo run --example e2e_client -- message --model "anthropic.claude-3-haiku-20240307-v1:0" --text "Hello!"

# Using API key authentication
cargo run --example e2e_client -- message --api-key "SSOK_your_api_key_here" --text "Hello!"

# Using Anthropic API format
cargo run --example e2e_client -- message --anthropic --text "Hello, how are you?"
```

### Interactive Chat
Start an interactive chat session:
```bash
# Standard chat through proxy
cargo run --example e2e_client -- chat

# Streaming chat
cargo run --example e2e_client -- chat --streaming

# Different model
cargo run --example e2e_client -- chat --model "anthropic.claude-3-haiku-20240307-v1:0"

# Chat with API key authentication
cargo run --example e2e_client -- chat --api-key "SSOK_your_api_key_here"

# Chat using Anthropic API format
cargo run --example e2e_client -- chat --anthropic
```

In interactive mode:
- Type messages and press Enter to send
- Type `quit` or `exit` to end the chat session

### Direct API Connection
The client can also connect directly to upstream APIs for testing:

```bash
# Connect directly to AWS Bedrock
cargo run --example e2e_client -- message --direct --text "Hello!"

# Connect directly to Anthropic API
cargo run --example e2e_client -- message --direct --anthropic --api-key "your-anthropic-key" --text "Hello!"
```

### Command Options

**Global Options:**
- `--config <CONFIG>`: Configuration file path (default: `config.yaml`)
- `--server-url <SERVER_URL>`: Proxy server URL (default: `http://localhost:3000`)
- `--direct`: Connect directly to upstream API instead of through proxy
- `--model <MODEL>`: Model to use for requests
- `--anthropic`: Use Anthropic API format (default: Bedrock format)
- `--api-key <API_KEY>`: API key for authentication (SSOK_ prefix for proxy, or Anthropic key for direct)
- `--streaming`: Enable streaming responses

**Available Models:**
- `anthropic.claude-sonnet-4-20250514-v1:0` (default)
- `anthropic.claude-3-haiku-20240307-v1:0`
- `anthropic.claude-3-opus-20240229-v1:0`
- Any other Bedrock model ID

## Features

- **Dual Mode Support**: Test both proxy and direct API connections
- **Multiple Authentication Methods**: JWT tokens and API keys
- **API Format Support**: Both AWS Bedrock and Anthropic API formats
- **JWT Authentication**: Automatically generates JWT tokens using the secret from config.yaml
- **API Key Authentication**: Support for proxy API keys (SSOK_ prefix) and direct Anthropic keys
- **Standard API**: Tests the `/bedrock/model/{model_id}/invoke` and `/anthropic/v1/messages` endpoints
- **Streaming API**: Tests streaming endpoints for both formats
- **Health Checks**: Tests the `/health` endpoint
- **Interactive Chat**: Continuous conversation with models
- **Error Handling**: Displays detailed error messages and status codes
- **Pretty Output**: Formats model responses nicely

## Examples

```bash
# Test health
cargo run --example e2e_client -- health

# Quick test message through proxy
cargo run --example e2e_client -- message --text "What is 2+2?"

# Streaming response with API key
cargo run --example e2e_client -- message --api-key "SSOK_your_key" --text "Tell me a story" --streaming

# Interactive chat using Anthropic format
cargo run --example e2e_client -- chat --anthropic

# Test with different server
cargo run --example e2e_client -- --server-url http://localhost:8080 chat

# Use different config file
cargo run --example e2e_client -- --config production.yaml chat

# Direct connection to Anthropic API
cargo run --example e2e_client -- message --direct --anthropic --api-key "your-anthropic-key" --text "Hello!"

# Direct connection to AWS Bedrock
cargo run --example e2e_client -- message --direct --text "Hello!"
```

## Troubleshooting

**"Failed to load config"**: Ensure `config.yaml` exists and has proper YAML syntax.

**"Connection refused"**: Make sure the proxy server is running on the expected port.

**"Unauthorized"**: Check that the JWT secret in the config matches the server's configuration.

**"AWS errors"**: Verify your AWS credentials and that you have access to Bedrock in the specified region.