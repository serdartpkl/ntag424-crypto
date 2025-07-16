/**
 * Structured Error Types for NTAG424 Crypto Library
 * 
 * Provides comprehensive error handling with proper error codes,
 * context information, and troubleshooting guidance.
 */

/**
 * Base NTAG424 Error Class
 * 
 * All library errors inherit from this base class to provide
 * consistent error structure and metadata.
 */
class NTAG424Error extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'NTAG424Error';
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      details: this.details,
      timestamp: this.timestamp,
      stack: this.stack
    };
  }
}

/**
 * Validation Error
 * 
 * Thrown when input validation fails (invalid hex, wrong lengths, etc.)
 */
class ValidationError extends NTAG424Error {
  constructor(message, field, value, expected = null) {
    super(message, 'VALIDATION_ERROR', { field, value, expected });
    this.name = 'ValidationError';
  }
}

/**
 * Decryption Error
 * 
 * Thrown when decryption process fails at any step
 */
class DecryptionError extends NTAG424Error {
  constructor(message, step, context = {}) {
    super(message, 'DECRYPTION_ERROR', { step, ...context });
    this.name = 'DecryptionError';
  }
}

/**
 * Encryption Error
 * 
 * Thrown when encryption process fails at any step
 */
class EncryptionError extends NTAG424Error {
  constructor(message, step, context = {}) {
    super(message, 'ENCRYPTION_ERROR', { step, ...context });
    this.name = 'EncryptionError';
  }
}

/**
 * SDM Profile Error
 * 
 * Thrown when SDM profile validation fails or incompatible operations are attempted
 */
class SDMProfileError extends NTAG424Error {
  constructor(message, profile, operation) {
    super(message, 'SDM_PROFILE_ERROR', { profile, operation });
    this.name = 'SDMProfileError';
  }
}

/**
 * Security Error
 * 
 * Thrown when security-related issues are detected
 */
class SecurityError extends NTAG424Error {
  constructor(message, threat, context = {}) {
    super(message, 'SECURITY_ERROR', { threat, ...context });
    this.name = 'SecurityError';
  }
}

/**
 * Error Helper Functions
 */
class ErrorHelper {
  /**
   * Get troubleshooting tips for common errors
   */
  static getTroubleshootingTips(error) {
    const tips = {
      'VALIDATION_ERROR': [
        'Check input format and required fields',
        'Ensure hex strings have correct length',
        'Verify UID starts with 04 for NFC Type A tags'
      ],
      'DECRYPTION_ERROR': [
        'Verify master key is correct',
        'Check for data corruption during transmission',
        'Ensure SDM profile matches the tag configuration'
      ],
      'ENCRYPTION_ERROR': [
        'Validate input parameters',
        'Check SDM profile compatibility',
        'Ensure master key is valid hex string'
      ],
      'SDM_PROFILE_ERROR': [
        'Use "full" profile for file data encryption',
        'Check profile supports required data types',
        'Verify custom profile configuration'
      ],
      'SECURITY_ERROR': [
        'Check for timing attack attempts',
        'Verify data integrity',
        'Review security configuration'
      ]
    };
    
    return tips[error.code] || ['Check documentation for common issues'];
  }

  /**
   * Create error context for debugging
   */
  static createContext(operation, input, options = {}) {
    return {
      operation,
      inputType: typeof input,
      inputLength: input?.length || 0,
      timestamp: new Date().toISOString(),
      options: Object.keys(options)
    };
  }

  /**
   * Sanitize error details for logging (remove sensitive data)
   */
  static sanitizeForLogging(error) {
    const sanitized = { ...error };
    
    // Remove sensitive data from error details
    if (sanitized.details) {
      if (sanitized.details.masterKey) {
        sanitized.details.masterKey = '[REDACTED]';
      }
      if (sanitized.details.value && typeof sanitized.details.value === 'string' && sanitized.details.value.length === 32) {
        sanitized.details.value = '[REDACTED_KEY]';
      }
    }
    
    return sanitized;
  }
}

module.exports = {
  NTAG424Error,
  ValidationError,
  DecryptionError,
  EncryptionError,
  SDMProfileError,
  SecurityError,
  ErrorHelper
};
