/**
 * Secure Memory Management for NTAG424 Crypto Library
 * 
 * Provides secure buffer handling with automatic cleanup and
 * timing attack protection for sensitive cryptographic operations.
 */

const crypto = require('crypto');
const { SecurityError } = require('./error-types');

/**
 * Secure Buffer - manages sensitive data in memory with automatic cleanup
 */
class SecureBuffer {
  /**
   * @param {number} size - Buffer size in bytes
   */
  constructor(size) {
    this.buffer = Buffer.alloc(size);
    this.size = size;
    this.cleared = false;
  }

  /**
   * Get buffer data - throws if already cleared
   * @returns {Buffer} The buffer data
   */
  get data() {
    if (this.cleared) {
      throw new SecurityError(
        'Attempted to access cleared secure buffer',
        'MEMORY_ACCESS_VIOLATION'
      );
    }
    return this.buffer;
  }

  /**
   * Clear buffer with secure overwrite
   */
  clear() {
    if (!this.cleared) {
      this.buffer.fill(0);
      this.cleared = true;
    }
  }
}

/**
 * Memory Manager - manages secure buffers and provides timing attack protection
 */
class MemoryManager {
  /**
   * @param {Object} options - Configuration options
   */
  constructor(options = {}) {
    this.secureBuffers = new Set();
  }

  /**
   * Create a new secure buffer
   * @param {number} size - Buffer size in bytes
   * @returns {SecureBuffer} New secure buffer
   */
  createSecureBuffer(size) {
    const buffer = new SecureBuffer(size);
    this.secureBuffers.add(buffer);
    return buffer;
  }

  /**
   * Clear all managed secure buffers
   */
  clearAll() {
    for (const buffer of this.secureBuffers) {
      try {
        buffer.clear();
      } catch (error) {
        // Continue clearing other buffers even if one fails
      }
    }
    this.secureBuffers.clear();
  }

  /**
   * Timing-safe equality comparison - compares two buffers in constant time
   * @param {Buffer} a - First buffer
   * @param {Buffer} b - Second buffer
   * @returns {boolean} True if buffers are equal
   */
  static timingSafeEqual(a, b) {
    try {
      if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
        return false;
      }
      
      if (a.length !== b.length) {
        return false;
      }
      
      return crypto.timingSafeEqual(a, b);
    } catch (error) {
      return false;
    }
  }

  /**
   * Constant time delay for security - adds a consistent delay to prevent timing attacks
   * @param {number} ms - Delay in milliseconds
   */
  static constantTimeDelay(ms = 1) {
    const start = Date.now();
    while (Date.now() - start < ms) {
      // Busy wait for constant time
    }
  }
}

module.exports = {
  SecureBuffer,
  MemoryManager
};
