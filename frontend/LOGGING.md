# Frontend Logging System

## Overview

The frontend uses a structured logging system with configurable log levels and context-aware loggers.

## Log Levels

- `ERROR` (0): Critical errors that need immediate attention
- `WARN` (1): Warning messages for potential issues
- `INFO` (2): General informational messages
- `DEBUG` (3): Detailed debugging information

## Available Loggers

- `logger`: General purpose logger
- `authLogger`: Authentication-specific logger (🔐 AUTH prefix)
- `appLogger`: Application-specific logger (📱 APP prefix)

## Configuration

### Environment Variable
Set log level in `.env`:
```bash
VITE_LOG_LEVEL=debug
```

### Runtime Control
Control logging from browser console:
```javascript
// Enable debug mode
enableDebugMode()

// Disable debug mode (reset to INFO level)
disableDebugMode()

// Or set localStorage directly
localStorage.setItem('log_level', 'debug')
localStorage.removeItem('log_level')
```

## Usage Examples

```typescript
import { authLogger, appLogger, logger } from '../utils/logger';

// Authentication events
authLogger.info('User login successful', { provider: 'google', userId: '123' });
authLogger.debug('Token refresh attempted', { expiresAt: timestamp });
authLogger.error('Authentication failed', { error: errorMessage });

// Application events
appLogger.debug('Component rendered', { isAuthenticated: true });
appLogger.warn('Performance issue detected', { loadTime: 3000 });

// General logging
logger.info('Operation completed', { duration: 1500 });
```

## Default Behavior

- **Production**: INFO level (shows ERROR, WARN, INFO)
- **Development**: DEBUG level (shows all logs)
- **Customizable**: Via environment variable or localStorage

## Log Format

```
2024-01-15T10:30:45.123Z [🔐 AUTH] DEBUG: Authentication successful {provider: 'google', user: 'user123'}
```

- Timestamp (ISO format)
- Logger prefix (if configured)
- Log level
- Message
- Optional data object