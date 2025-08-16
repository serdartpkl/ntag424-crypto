/**
 * Error Types for NTAG424 Crypto Library
 * 
 * Provides structured error handling with proper error codes and context information.
 */

/**
 * Base NTAG424 Error Class
 */
class NTAG424Error extends Error {
  /**
   * @param {string} message - Error message
   * @param {string} code - Error code
   * @param {Object} details - Additional error details
   */
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
      timestamp: this.timestamp
    };
  }
}

/**
 * Validation Error - thrown when input validation fails
 */
class ValidationError extends NTAG424Error {
  /**
   * @param {string} message - Error message
   * @param {string} field - Field that failed validation
   * @param {*} value - Invalid value
   * @param {*} expected - Expected value/format
   */
  constructor(message, field, value, expected = null) {
    super(message, 'VALIDATION_ERROR', { field, value, expected });
    this.name = 'ValidationError';
  }
}

/**
 * Decryption Error - thrown when decryption process fails
 */
class DecryptionError extends NTAG424Error {
  /**
   * @param {string} message - Error message
   * @param {string} step - Decryption step that failed
   * @param {Object} context - Additional context
   */
  constructor(message, step, context = {}) {
    super(message, 'DECRYPTION_ERROR', { step, ...context });
    this.name = 'DecryptionError';
  }
}

/**
 * Encryption Error - thrown when encryption process fails
 */
class EncryptionError extends NTAG424Error {
  /**
   * @param {string} message - Error message
   * @param {string} step - Encryption step that failed
   * @param {Object} context - Additional context
   */
  constructor(message, step, context = {}) {
    super(message, 'ENCRYPTION_ERROR', { step, ...context });
    this.name = 'EncryptionError';
  }
}

/**
 * SDM Profile Error - thrown when SDM profile validation fails
 */
class SDMProfileError extends NTAG424Error {
  /**
   * @param {string} message - Error message
   * @param {string|Object} profile - Profile that caused the error
   * @param {string} operation - Operation being performed
   */
  constructor(message, profile, operation) {
    super(message, 'SDM_PROFILE_ERROR', { profile, operation });
    this.name = 'SDMProfileError';
  }
}

/**
 * Security Error - thrown when security-related issues are detected
 */
class SecurityError extends NTAG424Error {
  /**
   * @param {string} message - Error message
   * @param {string} threat - Type of security threat
   * @param {Object} context - Additional context
   */
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
   * Create error context for debugging
   * @param {string} operation - Operation being performed
   * @param {*} input - Input data
   * @param {Object} options - Operation options
   * @returns {Object} Error context
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
   * @param {Error} error - Error to sanitize
   * @returns {Object} Sanitized error
   */
  static sanitizeForLogging(error) {
    const sanitized = { ...error };
    
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
