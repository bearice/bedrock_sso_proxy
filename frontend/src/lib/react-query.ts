import { QueryClient } from '@tanstack/react-query';

// Create a client
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Don't refetch on window focus by default
      refetchOnWindowFocus: false,
      // Retry failed requests once
      retry: 1,
      // Cache for 5 minutes by default
      staleTime: 1000 * 60 * 5,
    },
  },
});
