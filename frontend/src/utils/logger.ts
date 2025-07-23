// Logging levels
export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3
}

// Logger configuration
interface LoggerConfig {
  level: LogLevel;
  enableConsole: boolean;
  prefix?: string;
}

class Logger {
  private config: LoggerConfig;

  constructor(config: LoggerConfig) {
    this.config = config;
  }

  private shouldLog(level: LogLevel): boolean {
    return level <= this.config.level && this.config.enableConsole;
  }

  private formatMessage(level: string, message: string, context?: string): string {
    const timestamp = new Date().toISOString();
    const prefix = this.config.prefix ? `[${this.config.prefix}]` : '';
    const contextStr = context ? `[${context}]` : '';
    return `${timestamp} ${prefix}${contextStr} ${level}: ${message}`;
  }

  error(message: string, data?: unknown, context?: string): void {
    if (this.shouldLog(LogLevel.ERROR)) {
      console.error(this.formatMessage('ERROR', message, context), data || '');
    }
  }

  warn(message: string, data?: unknown, context?: string): void {
    if (this.shouldLog(LogLevel.WARN)) {
      console.warn(this.formatMessage('WARN', message, context), data || '');
    }
  }

  info(message: string, data?: unknown, context?: string): void {
    if (this.shouldLog(LogLevel.INFO)) {
      console.info(this.formatMessage('INFO', message, context), data || '');
    }
  }

  debug(message: string, data?: unknown, context?: string): void {
    if (this.shouldLog(LogLevel.DEBUG)) {
      console.log(this.formatMessage('DEBUG', message, context), data || '');
    }
  }
}

// Create logger instances
const getLogLevel = (): LogLevel => {
  // Safe way to access Vite environment variables
  const envLevel = (import.meta as { env?: { VITE_LOG_LEVEL?: string } }).env?.VITE_LOG_LEVEL;
  const localStorageLevel = typeof window !== 'undefined' ? localStorage.getItem('log_level') : null;
  const level = envLevel || localStorageLevel || 'info';
  
  switch (level.toLowerCase()) {
    case 'error': return LogLevel.ERROR;
    case 'warn': return LogLevel.WARN;
    case 'info': return LogLevel.INFO;
    case 'debug': return LogLevel.DEBUG;
    default: return LogLevel.INFO;
  }
};

// Default logger
export const logger = new Logger({
  level: getLogLevel(),
  enableConsole: true
});

// Auth-specific logger
export const authLogger = new Logger({
  level: getLogLevel(),
  enableConsole: true,
  prefix: '🔐 AUTH'
});

// App-specific logger  
export const appLogger = new Logger({
  level: getLogLevel(),
  enableConsole: true,
  prefix: '📱 APP'
});

// Utility functions for debugging
export const enableDebugMode = () => {
  localStorage.setItem('log_level', 'debug');
  window.location.reload();
};

export const disableDebugMode = () => {
  localStorage.removeItem('log_level');
  window.location.reload();
};

// Make debug functions available globally for console access
if (typeof window !== 'undefined') {
  (window as typeof window & { enableDebugMode?: typeof enableDebugMode; disableDebugMode?: typeof disableDebugMode }).enableDebugMode = enableDebugMode;
  (window as typeof window & { enableDebugMode?: typeof enableDebugMode; disableDebugMode?: typeof disableDebugMode }).disableDebugMode = disableDebugMode;
}