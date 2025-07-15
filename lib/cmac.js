const crypto = require('crypto');

let aesCmac;
try {
  const { aesCmac: importedAesCmac } = require('node-aes-cmac');
  aesCmac = importedAesCmac;
} catch (error) {
  // Fallback implementation for testing
  aesCmac = (key, data) => {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest().slice(0, 16);
  };
  console.warn('Warning: Using fallback CMAC implementation. Install node-aes-cmac for production use.');
}

/**
 * CMAC (Cipher-based Message Authentication Code) Operations
 * 
 * Provides AES-CMAC calculation and verification using the node-aes-cmac library.
 * CMAC is essential for NTAG424 authentication and data integrity verification.
 */
class CMAC {
  
  /**
   * Calculate AES-CMAC for given data
   * 
   * Computes the AES-CMAC authentication code for the provided data using the
   * specified key. Uses the node-aes-cmac library for standards-compliant implementation.
   * 
   * @param {Buffer} key - 16-byte AES key for CMAC calculation
   * @param {Buffer} data - Data to authenticate
   * @returns {Buffer} 16-byte CMAC value
   * 
   * @example
   * const key = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
   * const data = Buffer.from('Hello World');
   * const cmac = CMAC.calculate(key, data);
   */
  static calculate(key, data) {
    try {
      if (!Buffer.isBuffer(key) || key.length !== 16) {
        throw new Error('Key must be a 16-byte Buffer');
      }
      if (!Buffer.isBuffer(data)) {
        throw new Error('Data must be a Buffer');
      }
      
      const result = aesCmac(key, data);
      
      if (Buffer.isBuffer(result)) {
        return result;
      } else if (result && result.buffer) {
        return Buffer.from(result);
      } else if (typeof result === 'string') {
        return Buffer.from(result, 'hex');
      } else {
        return Buffer.from(result);
      }
    } catch (error) {
      throw new Error(`CMAC calculation failed: ${error.message}`);
    }
  }
  
  /**
   * Verify CMAC authenticity
   * 
   * Verifies that the provided CMAC matches the calculated CMAC for the given data.
   * Performs constant-time comparison to prevent timing attacks.
   * 
   * @param {Buffer} key - 16-byte AES key used for CMAC
   * @param {Buffer} data - Data that was authenticated
   * @param {Buffer} expectedMac - Expected CMAC value to verify against
   * @returns {boolean} True if CMAC is valid, false otherwise
   * 
   * @example
   * const isValid = CMAC.verify(key, data, receivedCmac);
   * if (isValid) {
   *   console.log('Data is authentic');
   * }
   */
  static verify(key, data, expectedMac) {
    try {
      if (!Buffer.isBuffer(key) || key.length !== 16) {
        return false;
      }
      if (!Buffer.isBuffer(data)) {
        return false;
      }
      if (!Buffer.isBuffer(expectedMac)) {
        return false;
      }
      
      const calculatedMac = aesCmac(key, data);
      let calculatedBuffer;
      
      if (Buffer.isBuffer(calculatedMac)) {
        calculatedBuffer = calculatedMac;
      } else if (calculatedMac && calculatedMac.buffer) {
        calculatedBuffer = Buffer.from(calculatedMac);
      } else if (typeof calculatedMac === 'string') {
        calculatedBuffer = Buffer.from(calculatedMac, 'hex');
      } else {
        calculatedBuffer = Buffer.from(calculatedMac);
      }
      
      const truncatedMac = calculatedBuffer.slice(0, expectedMac.length);
      
      if (truncatedMac.length !== expectedMac.length) {
        return false;
      }
      
      return crypto.timingSafeEqual(truncatedMac, expectedMac);
    } catch (error) {
      return false;
    }
  }
}

module.exports = CMAC;
