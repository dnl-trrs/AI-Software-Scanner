/**
 * Utilities Module
 * 
 * This module contains utility functions and helpers including:
 * - File system operations
 * - Configuration management
 * - Logging utilities
 * - Common helper functions
 */

export class Logger {
  static info(message: string): void {
    console.log(`[AI Scanner] INFO: ${message}`);
  }

  static warn(message: string): void {
    console.log(`[AI Scanner] WARN: ${message}`);
  }

  static error(message: string, error?: Error): void {
    console.log(`[AI Scanner] ERROR: ${message}`);
    if (error) {
      console.error(error);
    }
  }
}

export class ConfigManager {
  // Configuration management utilities
  // Implementation will be added in later milestones
}

export class FileUtils {
  // File system utilities
  // Implementation will be added in later milestones
}