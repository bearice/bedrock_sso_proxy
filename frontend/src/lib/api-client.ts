import createClient from 'openapi-fetch';
import type { paths } from '../generated/api';

// Create the API client with proper typing
export const apiClient = createClient<paths>({
  baseUrl: '', // Proxied by Vite dev server or served from same origin in production
});

// Helper to set authentication token
export function setAuthToken(token: string) {
  apiClient.use({
    onRequest(req) {
      if (req instanceof Request) {
        req.headers.set('Authorization', `Bearer ${token}`);
      }
      return undefined;
    },
  });
}

// Helper to clear authentication token
export function clearAuthToken() {
  // Reset the client middleware by providing an empty middleware function
  apiClient.use({
    onRequest() {
      return undefined;
    },
  });
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
