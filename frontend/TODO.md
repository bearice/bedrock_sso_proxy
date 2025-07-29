# Frontend Update TODO

## Overview
Update frontend to support new backend features: JWT renewal (✅ already implemented), API key management, and token usage tracking.

## Phase 1: Types & Services Setup

### 1.1 Update Types (`src/types/`)
- [ ] Add API key types to `auth.ts`:
  - `CreateApiKeyRequest` - name, expires_in_days
  - `CreateApiKeyResponse` - id, name, key, created_at, expires_at
  - `ApiKeyInfo` - id, name, created_at, expires_at, revoked_at
- [ ] Create `usage.ts` for usage tracking types:
  - `UsageRecord` - id, user_id, model_id, tokens, created_at, success
  - `UsageStats` - total_requests, total_tokens, success_rate, models
  - `UsageQuery` - limit, offset, model, start_date, end_date, success_only
  - `UsageRecordsResponse` - records, total, limit, offset

### 1.2 Extend API Services (`src/services/api.ts`)
- [ ] Add API key management functions:
  - `createApiKey(request: CreateApiKeyRequest)`
  - `listApiKeys()`
  - `revokeApiKey(keyId: string)`
- [ ] Add usage tracking functions:
  - `getUserUsageRecords(query?: UsageQuery)`
  - `getUserUsageStats(query?: UsageStatsQuery)`
- [ ] Add admin usage functions (for future admin panel):
  - `getSystemUsageRecords(query?: UsageQuery)`
  - `getSystemUsageStats(query?: UsageStatsQuery)`
  - `getTopModels(query?: UsageStatsQuery)`

## Phase 2: API Key Management Components

### 2.1 Core Components (`src/components/apikeys/`)
- [ ] `ApiKeyManagement.tsx` - Main container component
  - List existing keys
  - Create new key button
  - Handle loading/error states
- [ ] `ApiKeyCard.tsx` - Individual key display
  - Show key info (name, created, expires)
  - Copy key functionality (only for newly created)
  - Revoke key action
  - Status indicators (active/expired/revoked)
- [ ] `CreateApiKeyModal.tsx` - Key creation modal
  - Form with name and expiration
  - Validation (name required, max length)
  - Show newly created key with copy functionality
  - Warning about key visibility

### 2.2 API Key Features
- [ ] Key expiration handling and warnings
- [ ] Copy to clipboard functionality
- [ ] Confirmation dialogs for revocation
- [ ] Loading states during operations
- [ ] Error handling and user feedback

## Phase 3: Usage Tracking Components

### 3.1 Core Components (`src/components/usage/`)
- [ ] `UsageTracking.tsx` - Main usage dashboard
  - Usage statistics overview
  - Recent usage records table
  - Filter controls
- [ ] `UsageStats.tsx` - Statistics display
  - Total requests/tokens
  - Success rate
  - Model breakdown
- [ ] `UsageRecords.tsx` - Records table
  - Sortable columns (date, model, tokens, status)
  - Pagination controls
  - Status indicators (success/failure)
- [ ] `UsageFilters.tsx` - Filter controls
  - Date range picker
  - Model selection
  - Success/failure filter
  - Clear filters action

### 3.2 Usage Features  
- [ ] Date range filtering with presets (today, week, month)
- [ ] Model usage breakdown with visual indicators
- [ ] Export functionality (CSV/JSON)
- [ ] Real-time usage updates
- [ ] Pagination for large datasets

## Phase 4: Dashboard Integration

### 4.1 Dashboard Layout (`src/pages/DashboardPage.tsx`)
- [ ] Add tabbed interface for different sections:
  - Overview (current content)
  - API Keys
  - Usage Tracking
- [ ] Responsive navigation between sections
- [ ] Update welcome section with new features

### 4.2 Navigation & UX
- [ ] Tab component for section switching
- [ ] Breadcrumb navigation
- [ ] Mobile-responsive design
- [ ] Loading states for each section
- [ ] Empty states with helpful messages

## Phase 5: Enhanced Features

### 5.1 Advanced API Key Features
- [ ] Bulk operations (revoke multiple keys)
- [ ] Key usage analytics (track which keys are used)
- [ ] Key permissions/scopes (future enhancement)
- [ ] Key rotation reminders

### 5.2 Advanced Usage Features
- [ ] Usage visualization charts (line/bar charts)
- [ ] Cost estimation based on usage
- [ ] Usage alerts/notifications
- [ ] Model performance analytics
- [ ] Comparative usage analysis

## Phase 6: Polish & Testing

### 6.1 Code Quality
- [ ] TypeScript strict mode compliance
- [ ] ESLint/Prettier formatting
- [ ] Component prop validation
- [ ] Error boundary implementation

### 6.2 User Experience
- [ ] Loading skeletons for better perceived performance
- [ ] Toast notifications for actions
- [ ] Form validation with helpful error messages
- [ ] Keyboard navigation support
- [ ] Accessibility improvements (ARIA labels, focus management)

### 6.3 Testing
- [ ] Unit tests for utility functions
- [ ] Component testing with React Testing Library
- [ ] Integration tests for API calls
- [ ] E2E testing for critical user flows

## Phase 7: Documentation & Deployment

### 7.1 Documentation
- [ ] Update component documentation
- [ ] API integration examples
- [ ] User guide for new features
- [ ] Developer setup instructions

### 7.2 Build & Deploy
- [ ] Verify production build
- [ ] Test with backend integration
- [ ] Performance optimization
- [ ] Bundle size analysis

## Dependencies to Add

Consider adding these packages for enhanced functionality:
- [ ] `react-query` or `swr` for data fetching/caching
- [ ] `react-hook-form` for form management
- [ ] `date-fns` for date manipulation
- [ ] `recharts` or `chart.js` for usage visualization
- [ ] `react-table` for advanced table features

## Notes

- JWT renewal is already implemented in `AuthContext.tsx` ✅
- All backend APIs are available and tested
- Follow existing code patterns and styling
- Maintain responsive design principles
- Ensure proper error handling throughout
- Consider implementing optimistic updates for better UX

## Priority

**High Priority:**
- Phase 1 (Types & Services)
- Phase 2 (API Key Management)
- Phase 4 (Dashboard Integration)

**Medium Priority:**
- Phase 3 (Usage Tracking)
- Phase 6 (Polish & Testing)

**Low Priority:**
- Phase 5 (Enhanced Features)
- Phase 7 (Documentation)