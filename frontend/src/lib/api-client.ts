import createClient from 'openapi-fetch';
import type { paths } from '../generated/api';

// Global variable to store current auth token
let currentAuthToken: string | null = null;

// Create the API client with proper typing and set up persistent middleware
export const apiClient = createClient<paths>({
  baseUrl: '', // Proxied by Vite dev server or served from same origin in production
});

// Set up persistent middleware that checks for the current token
apiClient.use({
  onRequest(req: any) {
    // Always check for the latest token at request time
    const authData = typeof window !== 'undefined' ? localStorage.getItem('bedrock_auth') : null;
    let token = currentAuthToken;

    // Fallback to localStorage if the global token isn't set yet
    if (!token && authData) {
      try {
        const parsed = JSON.parse(authData);
        if (parsed.isAuthenticated && parsed.token) {
          token = parsed.token;
          // Update the global token for subsequent requests
          currentAuthToken = token;
        }
      } catch (e) {
        console.error('Failed to parse auth data from localStorage:', e);
      }
    }

    if (token) {
      // Handle openapi-fetch request object structure
      if (req && req.request instanceof Request) {
        req.request.headers.set('Authorization', `Bearer ${token}`);
      } else if (req instanceof Request) {
        req.headers.set('Authorization', `Bearer ${token}`);
      }
    }
    
    return undefined;
  },
});

// Helper to set authentication token
export function setAuthToken(token: string) {
  currentAuthToken = token;
}

// Helper to clear authentication token
export function clearAuthToken() {
  currentAuthToken = null;
}

// Helper to handle errors consistently
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}
