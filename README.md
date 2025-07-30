# Bedrock SSO Proxy

A secure proxy server originally designed to enable Claude Code users to access AWS Bedrock APIs through their corporate SSO providers, with real-time cost and usage tracking that AWS lacks.

## 🎯 Why Use This?

- **Claude Code Integration**: Originally built to let Claude Code users access Bedrock models through corporate SSO
- **Use Your SSO**: Login with Google, GitHub, Microsoft, etc. to generate API keys
- **Real-time Cost Tracking**: See spending as it happens, not days later in AWS billing
- **Usage Analytics**: Track who's using what models and how much
- **API Key Management**: Create, rotate, and revoke keys through web interface

## 🚀 Quick Start

1. **Set up AWS credentials** (IAM user with Bedrock access or EC2 instance role)

2. **Create configuration file** `config/local.yaml`:
   ```yaml
   aws:
     region: "us-east-1"
     # Optional: specify credentials (otherwise uses default AWS credential chain)
     # access_key_id: "your-access-key"
     # secret_access_key: "your-secret-key"
   
   oauth:
     google:
       client_id: "your-google-client-id"
       client_secret: "your-google-client-secret"
   ```

3. **Run the server**:
   ```bash
   cargo run --bin bedrock_proxy
   ```

4. **Access the web interface**: http://localhost:3000
5. **Login with SSO and create an API key**
6. **Use your API key with applications**:

## 📖 API Usage

**Bedrock Format**:
```bash
curl -X POST "http://localhost:3000/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke" \
  -H "Authorization: Bearer SSOK_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

**Anthropic Format**:
```bash
curl -X POST "http://localhost:3000/anthropic/v1/messages" \
  -H "X-API-Key: SSOK_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## ⚙️ Configuration

Create `config/local.yaml`:

```yaml
server:
  port: 3000

aws:
  region: "us-east-1"

oauth:
  google:
    client_id: "your-google-client-id"
    client_secret: "your-google-client-secret"
  
database:
  url: "sqlite://./data/bedrock_sso.db"
```

## 🧪 Development

```bash
cargo build              # Build project
cargo test               # Run tests (285+ tests)
cargo run --bin bedrock_proxy  # Run server
```

**Frontend development**:
```bash
cd frontend && npm install && npm run dev
```

## 📊 Features

- **Multiple SSO Providers**: Google, GitHub, Microsoft, GitLab, Auth0, Okta
- **Real-time Analytics**: Usage dashboard with cost breakdowns
- **API Compatibility**: Both Bedrock and Anthropic API formats
- **Streaming Support**: Server-sent events for real-time responses
- **Production Ready**: Health checks, metrics, graceful shutdown

## 🚢 Deployment

**Production build**:
```bash
cargo build --release
./target/release/bedrock_proxy
```

**Environment variables** (optional, use `BEDROCK_` prefix):
- `BEDROCK_AWS__REGION=us-east-1`
- `BEDROCK_OAUTH__GOOGLE__CLIENT_ID=your-id`

## 📄 API Documentation

Interactive API docs: http://localhost:3000/docs

---

**Built for organizations that need visibility into their AI infrastructure costs and usage.**

*Meta note: This project was itself built using Claude Code, burning through tokens like a jet engine with countless back-and-forth reviews. It's a fitting testament to why you need cost tracking for AI development!*