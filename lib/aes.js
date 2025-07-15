const crypto = require('crypto');

/**
 * AES Encryption/Decryption Operations
 * 
 * Provides AES encryption and decryption operations in CBC and ECB modes.
 * All operations use AES-128 with proper padding handling.
 */
class AES {
  
  /**
   * AES-128-CBC Encryption
   * 
   * Encrypts data using AES-128 in CBC mode with automatic PKCS7 padding.
   * 
   * @param {Buffer} key - 16-byte AES key
   * @param {Buffer} data - Data to encrypt
   * @param {Buffer} iv - Initialization vector (16 bytes). If null, uses zero IV
   * @returns {Buffer} Encrypted data
   * 
   * @example
   * const key = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
   * const data = Buffer.from('Hello World');
   * const encrypted = AES.cbcEncrypt(key, data);
   */
  static cbcEncrypt(key, data, iv = null) {
    try {
      const actualIV = iv || Buffer.alloc(16, 0x00);
      const cipher = crypto.createCipheriv('aes-128-cbc', key, actualIV);
      cipher.setAutoPadding(true);
      
      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      return encrypted;
    } catch (error) {
      throw new Error(`AES CBC encryption failed: ${error.message}`);
    }
  }
  
  /**
   * AES-128-CBC Decryption
   * 
   * Decrypts data using AES-128 in CBC mode with automatic PKCS7 padding removal.
   * 
   * @param {Buffer} key - 16-byte AES key
   * @param {Buffer} data - Data to decrypt
   * @param {Buffer} iv - Initialization vector (16 bytes). If null, uses zero IV
   * @returns {Buffer} Decrypted data
   * 
   * @example
   * const decrypted = AES.cbcDecrypt(key, encryptedData);
   */
  static cbcDecrypt(key, data, iv = null) {
    try {
      const actualIV = iv || Buffer.alloc(16, 0x00);
      const decipher = crypto.createDecipheriv('aes-128-cbc', key, actualIV);
      decipher.setAutoPadding(true);
      
      let decrypted = decipher.update(data);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted;
    } catch (error) {
      throw new Error(`AES CBC decryption failed: ${error.message}`);
    }
  }
  
  /**
   * AES-128-ECB Encryption
   * 
   * Encrypts data using AES-128 in ECB mode without padding.
   * Data must be exactly 16 bytes or a multiple thereof.
   * 
   * @param {Buffer} key - 16-byte AES key
   * @param {Buffer} data - Data to encrypt (must be 16-byte aligned)
   * @returns {Buffer} Encrypted data
   * 
   * @example
   * const encrypted = AES.ecbEncrypt(key, sixteenByteData);
   */
  static ecbEncrypt(key, data) {
    try {
      const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
      cipher.setAutoPadding(false);
      
      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      return encrypted;
    } catch (error) {
      throw new Error(`AES ECB encryption failed: ${error.message}`);
    }
  }
  
  /**
   * AES-128-ECB Decryption
   * 
   * Decrypts data using AES-128 in ECB mode without padding.
   * 
   * @param {Buffer} key - 16-byte AES key
   * @param {Buffer} data - Data to decrypt
   * @returns {Buffer} Decrypted data
   * 
   * @example
   * const decrypted = AES.ecbDecrypt(key, encryptedData);
   */
  static ecbDecrypt(key, data) {
    try {
      const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
      decipher.setAutoPadding(false);
      
      let decrypted = decipher.update(data);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted;
    } catch (error) {
      throw new Error(`AES ECB decryption failed: ${error.message}`);
    }
  }
}

module.exports = AES;
