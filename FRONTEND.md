# Frontend Development Guide

This guide explains how to develop and build the frontend for Bedrock SSO Proxy.

## Architecture

**Single Binary Deployment**: The frontend is embedded directly into the Rust binary using `rust-embed`, making deployment simple - just one executable file.

**Serving Modes**:
1. **Filesystem Mode**: Set `frontend.path` in config → serves from that directory
2. **Embedded Mode**: No config → serves from embedded assets (built from `frontend/dist/`)

## Quick Start

### 1. Create Your Frontend

Create your SPA in the `frontend/` directory:

```bash
# Example with React + Vite
npm create vite@latest frontend -- --template react-ts
cd frontend
npm install
```

### 2. Develop Your Frontend

```bash
cd frontend
npm run dev
```

Your frontend should:
- Call the backend API at `/auth/*` for OAuth
- Call the backend API at `/model/*` for Bedrock proxy
- Handle client-side routing for better UX

### 3. Build and Embed

```bash
# Run the build script (builds frontend + embeds + rebuilds binary)
./build-frontend.sh
```

This will:
1. Build your SPA (`npm run build`)
2. Rebuild the Rust binary with embedded assets from `frontend/dist/`

## Configuration Options

### Embedded Mode (Default)
```yaml
# No frontend config needed - uses embedded assets
```

### Filesystem Mode
```yaml
frontend:
  path: "./my-frontend-dist"  # Serve from this directory instead of embedded
```

Environment variable:
```bash
BEDROCK_FRONTEND__PATH=./my-frontend-dist
```

### 4. Run the Server

```bash
./target/release/bedrock_proxy
```

Your SPA will be served at `http://localhost:3000`

## Development Workflow

### Option 1: Separate Development
```bash
# Terminal 1: Backend
cargo run --bin bedrock_proxy

# Terminal 2: Frontend (with proxy to backend)
cd frontend
npm run dev
```

Configure your frontend dev server to proxy API calls to `http://localhost:3000`

### Option 2: Embedded Development
```bash
# Make changes to frontend
cd frontend
# ... edit files ...

# Rebuild and test
./build-frontend.sh
./target/release/bedrock_proxy
```

## Frontend Requirements

Your SPA should implement:

### 1. OAuth Authentication Flow
- Login page with provider buttons
- Handle OAuth callback (`/auth/callback/{provider}`)
- Store JWT tokens securely
- Token refresh logic

### 2. Token Management UI
- Display current JWT token
- Copy token to clipboard
- Refresh token functionality
- Claude Code integration instructions

### 3. API Integration
- Configure axios/fetch to use stored JWT
- Handle token expiration
- Proxy Bedrock API calls through the backend

## Example Frontend Structure

```
frontend/
├── package.json
├── vite.config.ts        # Configure API proxy for development
├── src/
│   ├── main.tsx         # App entry point
│   ├── App.tsx          # Main app component
│   ├── pages/
│   │   ├── LoginPage.tsx    # OAuth provider selection
│   │   ├── DashboardPage.tsx # Token management
│   │   └── SetupPage.tsx    # Claude Code instructions
│   ├── components/
│   │   ├── TokenDisplay.tsx
│   │   ├── OAuthButton.tsx
│   │   └── SetupInstructions.tsx
│   ├── hooks/
│   │   ├── useAuth.ts       # Authentication logic
│   │   └── useTokens.ts     # Token management
│   └── services/
│       ├── auth.ts          # OAuth API calls
│       └── api.ts           # Bedrock proxy calls
└── dist/                # Build output (copied to assets/frontend/)
```

## API Endpoints Your Frontend Can Use

### Authentication
- `GET /auth/providers` - List available OAuth providers
- `GET /auth/authorize/{provider}` - Start OAuth flow
- `POST /auth/token` - Exchange code for JWT
- `POST /auth/refresh` - Refresh JWT token

### Bedrock Proxy
- `POST /model/{model_id}/invoke` - Standard model invocation
- `POST /model/{model_id}/invoke-with-response-stream` - Streaming responses

### Utilities
- `GET /health` - Health check

## File Override System

Users can customize the frontend by placing files in `custom/`:

```bash
custom/
├── index.html           # Override main page
├── assets/
│   ├── styles.css       # Override styles
│   └── logo.png         # Override images
└── favicon.ico          # Override favicon
```

## Build Configuration

### Vite Example (`vite.config.ts`)
```typescript
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/auth': 'http://localhost:3000',
      '/model': 'http://localhost:3000',
      '/health': 'http://localhost:3000'
    }
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets'
  }
})
```

### Create React App Example
Configure proxy in `package.json`:
```json
{
  "proxy": "http://localhost:3000"
}
```

## Deployment

The built binary contains everything needed:
```bash
# Single file deployment
./bedrock_proxy
```

No need to serve static files separately - everything is embedded!