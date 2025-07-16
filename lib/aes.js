const crypto = require('crypto');
const { ValidationError, SecurityError } = require('./error-types');
const { MemoryManager } = require('./secure-memory');

/**
 * AES Encryption/Decryption Operations
 * 
 * Provides AES encryption and decryption operations in CBC and ECB modes.
 * All operations use AES-128 with proper padding handling and security measures.
 */
class AES {
  
  /**
   * AES-128-CBC Encryption
   * 
   * @param {Buffer} key - 16-byte AES key
   * @param {Buffer} data - Data to encrypt
   * @param {Buffer} iv - Initialization vector (16 bytes). If null, uses zero IV
   * @returns {Buffer} Encrypted data
   */
  static cbcEncrypt(key, data, iv = null) {
    try {
      if (!Buffer.isBuffer(key) || key.length !== 16) {
        throw new ValidationError('Key must be a 16-byte Buffer', 'key', key?.length, 16);
      }
      
      if (!Buffer.isBuffer(data)) {
        throw new ValidationError('Data must be a Buffer', 'data', typeof data, 'Buffer');
      }
      
      const actualIV = iv || Buffer.alloc(16, 0x00);
      
      if (!Buffer.isBuffer(actualIV) || actualIV.length !== 16) {
        throw new ValidationError('IV must be a 16-byte Buffer', 'iv', actualIV?.length, 16);
      }
      
      const cipher = crypto.createCipheriv('aes-128-cbc', key, actualIV);
      cipher.setAutoPadding(true);
      
      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      return encrypted;
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`AES CBC encryption failed: ${error.message}`, 'ENCRYPTION_FAILURE');
    }
  }
  
  /**
   * AES-128-CBC Decryption
   * 
   * @param {Buffer} key - 16-byte AES key
   * @param {Buffer} data - Data to decrypt
   * @param {Buffer} iv - Initialization vector (16 bytes). If null, uses zero IV
   * @returns {Buffer} Decrypted data
   */
  static cbcDecrypt(key, data, iv = null) {
    try {
      if (!Buffer.isBuffer(key) || key.length !== 16) {
        throw new ValidationError('Key must be a 16-byte Buffer', 'key', key?.length, 16);
      }
      
      if (!Buffer.isBuffer(data)) {
        throw new ValidationError('Data must be a Buffer', 'data', typeof data, 'Buffer');
      }
      
      if (data.length === 0) {
        throw new ValidationError('Data cannot be empty', 'data', 0, '>0');
      }
      
      if (data.length % 16 !== 0) {
        throw new ValidationError('Data length must be multiple of 16 bytes', 'data', data.length, 'multiple of 16');
      }
      
      const actualIV = iv || Buffer.alloc(16, 0x00);
      
      if (!Buffer.isBuffer(actualIV) || actualIV.length !== 16) {
        throw new ValidationError('IV must be a 16-byte Buffer', 'iv', actualIV?.length, 16);
      }
      
      const decipher = crypto.createDecipheriv('aes-128-cbc', key, actualIV);
      decipher.setAutoPadding(true);
      
      let decrypted = decipher.update(data);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted;
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      
      MemoryManager.constantTimeDelay(2);
      throw new SecurityError(`AES CBC decryption failed: ${error.message}`, 'DECRYPTION_FAILURE');
    }
  }
  
  /**
   * AES-128-ECB Encryption
   * 
   * @param {Buffer} key - 16-byte AES key
   * @param {Buffer} data - Data to encrypt (must be 16-byte aligned)
   * @returns {Buffer} Encrypted data
   */
  static ecbEncrypt(key, data) {
    try {
      if (!Buffer.isBuffer(key) || key.length !== 16) {
        throw new ValidationError('Key must be a 16-byte Buffer', 'key', key?.length, 16);
      }
      
      if (!Buffer.isBuffer(data)) {
        throw new ValidationError('Data must be a Buffer', 'data', typeof data, 'Buffer');
      }
      
      if (data.length % 16 !== 0) {
        throw new ValidationError('Data length must be multiple of 16 bytes for ECB mode', 'data', data.length, 'multiple of 16');
      }
      
      const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
      cipher.setAutoPadding(false);
      
      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      return encrypted;
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`AES ECB encryption failed: ${error.message}`, 'ENCRYPTION_FAILURE');
    }
  }
  
  /**
   * AES-128-ECB Decryption
   * 
   * @param {Buffer} key - 16-byte AES key
   * @param {Buffer} data - Data to decrypt
   * @returns {Buffer} Decrypted data
   */
  static ecbDecrypt(key, data) {
    try {
      if (!Buffer.isBuffer(key) || key.length !== 16) {
        throw new ValidationError('Key must be a 16-byte Buffer', 'key', key?.length, 16);
      }
      
      if (!Buffer.isBuffer(data)) {
        throw new ValidationError('Data must be a Buffer', 'data', typeof data, 'Buffer');
      }
      
      if (data.length % 16 !== 0) {
        throw new ValidationError('Data length must be multiple of 16 bytes for ECB mode', 'data', data.length, 'multiple of 16');
      }
      
      const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
      decipher.setAutoPadding(false);
      
      let decrypted = decipher.update(data);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted;
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      
      MemoryManager.constantTimeDelay(2);
      throw new SecurityError(`AES ECB decryption failed: ${error.message}`, 'DECRYPTION_FAILURE');
    }
  }
}

module.exports = AES;
