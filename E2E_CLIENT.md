# Bedrock SSO Proxy E2E Test Client

A command-line client for end-to-end testing of the Bedrock SSO Proxy server.

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
cargo build --bin bedrock_e2e_client
```

## Usage

### Health Check
Test if the proxy server is running:
```bash
cargo run --bin bedrock_e2e_client -- health
```

### Send Single Message
Send a single message to a model:
```bash
# Standard response
cargo run --bin bedrock_e2e_client -- message --text "Hello, how are you?"

# Streaming response
cargo run --bin bedrock_e2e_client -- message --text "Hello, how are you?" --streaming

# Different model
cargo run --bin bedrock_e2e_client -- message --model "anthropic.claude-3-haiku-20240307-v1:0" --text "Hello!"
```

### Interactive Chat
Start an interactive chat session:
```bash
# Standard chat
cargo run --bin bedrock_e2e_client -- chat

# Streaming chat
cargo run --bin bedrock_e2e_client -- chat --streaming

# Different model
cargo run --bin bedrock_e2e_client -- chat --model "anthropic.claude-3-haiku-20240307-v1:0"
```

In interactive mode:
- Type messages and press Enter to send
- Type `quit` or `exit` to end the chat session

### Command Options

**Global Options:**
- `--config <FILE>`: Configuration file path (default: `config.yaml`)
- `--server-url <URL>`: Proxy server URL (default: `http://localhost:3000`)

**Available Models:**
- `anthropic.claude-3-sonnet-20240229-v1:0` (default)
- `anthropic.claude-3-haiku-20240307-v1:0`
- `anthropic.claude-3-opus-20240229-v1:0`
- Any other Bedrock model ID

## Features

- **JWT Authentication**: Automatically generates JWT tokens using the secret from config.yaml
- **Standard API**: Tests the `/bedrock/model/{model_id}/invoke` endpoint
- **Streaming API**: Tests the `/bedrock/model/{model_id}/invoke-with-response-stream` endpoint
- **Health Checks**: Tests the `/health` endpoint
- **Interactive Chat**: Continuous conversation with models
- **Error Handling**: Displays detailed error messages and status codes
- **Pretty Output**: Formats model responses nicely

## Examples

```bash
# Test health
cargo run --bin bedrock_e2e_client -- health

# Quick test message
cargo run --bin bedrock_e2e_client -- message --text "What is 2+2?"

# Streaming response
cargo run --bin bedrock_e2e_client -- message --text "Tell me a story" --streaming

# Interactive chat with different server
cargo run --bin bedrock_e2e_client -- --server-url http://localhost:8080 chat

# Use different config file
cargo run --bin bedrock_e2e_client -- --config production.yaml chat
```

## Troubleshooting

**"Failed to load config"**: Ensure `config.yaml` exists and has proper YAML syntax.

**"Connection refused"**: Make sure the proxy server is running on the expected port.

**"Unauthorized"**: Check that the JWT secret in the config matches the server's configuration.

**"AWS errors"**: Verify your AWS credentials and that you have access to Bedrock in the specified region.