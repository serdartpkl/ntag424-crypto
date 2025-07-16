/**
 * Secure Memory Management for NTAG424 Crypto Library
 * 
 * Provides secure buffer handling with automatic cleanup and
 * timing attack protection for sensitive cryptographic operations.
 */

const crypto = require('crypto');
const { SecurityError } = require('./error-types');

/**
 * Secure Buffer
 * 
 * Manages sensitive data in memory with automatic cleanup
 * and protection against accidental access after clearing.
 */
class SecureBuffer {
  constructor(size) {
    this.buffer = Buffer.alloc(size);
    this.size = size;
    this.cleared = false;
  }

  /**
   * Get buffer data - throws if already cleared
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
   * Clear buffer with cryptographically secure overwrite
   */
  clear() {
    if (!this.cleared) {
      try {
        crypto.randomFillSync(this.buffer);
      } catch (error) {
        for (let i = 0; i < this.buffer.length; i++) {
          this.buffer[i] = Math.floor(Math.random() * 256);
        }
      }
      
      this.buffer.fill(0);
      this.cleared = true;
    }
  }

  /**
   * Finalize - alias for clear()
   */
  finalize() {
    this.clear();
  }
}

/**
 * Memory Manager
 * 
 * Manages secure buffers and provides timing attack protection
 */
class MemoryManager {
  constructor(options = {}) {
    this.secureBuffers = new Set();
    this.clearOnExit = options.clearOnExit !== false;
    this.listenersAdded = false;
    
    if (this.clearOnExit && !MemoryManager.globalListenersAdded) {
      this._addGlobalListeners();
    }
  }

  /**
   * Add global event listeners (only once)
   */
  _addGlobalListeners() {
    if (MemoryManager.globalListenersAdded) return;
    
    MemoryManager.globalListenersAdded = true;
    MemoryManager.globalManagers = new Set();
    
    const cleanup = () => {
      for (const manager of MemoryManager.globalManagers) {
        try {
          manager.clearAll();
        } catch (error) {
          // Continue cleanup even if one fails
        }
      }
      MemoryManager.globalManagers.clear();
    };
    
    process.on('exit', cleanup);
    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
    
    MemoryManager.globalManagers.add(this);
  }

  /**
   * Create a new secure buffer
   */
  createSecureBuffer(size) {
    const buffer = new SecureBuffer(size);
    this.secureBuffers.add(buffer);
    
    if (MemoryManager.globalManagers) {
      MemoryManager.globalManagers.add(this);
    }
    
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
    
    if (MemoryManager.globalManagers) {
      MemoryManager.globalManagers.delete(this);
    }
  }

  /**
   * Timing-safe equality comparison
   * 
   * Compares two buffers in constant time to prevent timing attacks
   */
  static timingSafeEqual(a, b) {
    try {
      if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
        return false;
      }
      
      const maxLength = Math.max(a.length, b.length);
      const padded1 = Buffer.alloc(maxLength);
      const padded2 = Buffer.alloc(maxLength);
      
      a.copy(padded1);
      b.copy(padded2);
      
      return crypto.timingSafeEqual(padded1, padded2);
    } catch (error) {
      const dummyBuffer = Buffer.alloc(16);
      try {
        crypto.timingSafeEqual(dummyBuffer, dummyBuffer);
      } catch (e) {
        MemoryManager.constantTimeDelay(1);
      }
      return false;
    }
  }

  /**
   * Constant time delay for security
   * 
   * Adds a consistent delay to prevent timing attacks
   */
  static constantTimeDelay(ms = 1) {
    const start = Date.now();
    while (Date.now() - start < ms) {
      // Busy wait for constant time
    }
  }

  /**
   * Secure buffer comparison with automatic cleanup
   */
  static compareAndClear(buffer1, buffer2) {
    try {
      const result = MemoryManager.timingSafeEqual(buffer1, buffer2);
      return result;
    } finally {
      if (buffer1 && buffer1.clear) {
        buffer1.clear();
      }
      if (buffer2 && buffer2.clear) {
        buffer2.clear();
      }
    }
  }
}

// Static properties for global listener management
MemoryManager.globalListenersAdded = false;
MemoryManager.globalManagers = null;

/**
 * Buffer Pool for Performance
 * 
 * Reuses buffers to reduce garbage collection pressure
 * while maintaining security through proper clearing
 */
class BufferPool {
  constructor(options = {}) {
    this.pools = new Map();
    this.maxPoolSize = options.maxPoolSize || 50;
    this.enableMetrics = options.enableMetrics || false;
    this.metrics = {
      hits: 0,
      misses: 0,
      created: 0,
      returned: 0
    };
  }

  /**
   * Get a buffer from the pool or create new one
   */
  getBuffer(size) {
    const sizeKey = size.toString();
    
    if (!this.pools.has(sizeKey)) {
      this.pools.set(sizeKey, []);
    }
    
    const pool = this.pools.get(sizeKey);
    
    if (pool.length > 0) {
      if (this.enableMetrics) this.metrics.hits++;
      return pool.pop();
    }
    
    if (this.enableMetrics) {
      this.metrics.misses++;
      this.metrics.created++;
    }
    
    return Buffer.alloc(size);
  }

  /**
   * Return a buffer to the pool after clearing it
   */
  returnBuffer(buffer) {
    if (!Buffer.isBuffer(buffer)) {
      throw new SecurityError(
        'Must return a Buffer object',
        'INVALID_BUFFER_RETURN',
        { actualType: typeof buffer }
      );
    }
    
    const size = buffer.length;
    const sizeKey = size.toString();
    
    if (!this.pools.has(sizeKey)) {
      this.pools.set(sizeKey, []);
    }
    
    const pool = this.pools.get(sizeKey);
    
    if (pool.length < this.maxPoolSize) {
      buffer.fill(0);
      pool.push(buffer);
      
      if (this.enableMetrics) this.metrics.returned++;
    }
  }

  /**
   * Get performance metrics
   */
  getMetrics() {
    return { ...this.metrics };
  }

  /**
   * Clear all pooled buffers
   */
  clear() {
    for (const [size, pool] of this.pools) {
      for (const buffer of pool) {
        buffer.fill(0);
      }
    }
    this.pools.clear();
    this.metrics = { hits: 0, misses: 0, created: 0, returned: 0 };
  }
}

module.exports = {
  SecureBuffer,
  MemoryManager,
  BufferPool
};
