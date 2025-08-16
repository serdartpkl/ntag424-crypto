/**
 * CMAC (Cipher-based Message Authentication Code) Operations
 * 
 * Provides AES-CMAC calculation and verification using the node-aes-cmac library.
 * CMAC is essential for NTAG424 authentication and data integrity verification.
 */

const { ValidationError, SecurityError } = require('./error-types');
const { MemoryManager } = require('./secure-memory');

let aesCmac;
try {
  const { aesCmac: importedAesCmac } = require('node-aes-cmac');
  aesCmac = importedAesCmac;
} catch (error) {
  throw new Error('node-aes-cmac is required for production use. Install with: npm install node-aes-cmac');
}

/**
 * CMAC Operations
 */
class CMAC {
  
  /**
   * Calculate AES-CMAC for given data
   * @param {Buffer} key - 16-byte AES key for CMAC calculation
   * @param {Buffer} data - Data to authenticate
   * @returns {Buffer} 16-byte CMAC value
   */
  static calculate(key, data) {
    try {
      if (!Buffer.isBuffer(key) || key.length !== 16) {
        throw new ValidationError('Key must be a 16-byte Buffer', 'key', key?.length, 16);
      }
      
      if (!Buffer.isBuffer(data)) {
        throw new ValidationError('Data must be a Buffer', 'data', typeof data, 'Buffer');
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
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`CMAC calculation failed: ${error.message}`, 'CMAC_CALCULATION_FAILURE');
    }
  }
  
  /**
   * Verify CMAC authenticity
   * @param {Buffer} key - 16-byte AES key used for CMAC
   * @param {Buffer} data - Data that was authenticated
   * @param {Buffer} expectedMac - Expected CMAC value to verify against
   * @returns {boolean} True if CMAC is valid, false otherwise
   */
  static verify(key, data, expectedMac) {
    try {
      if (!Buffer.isBuffer(key) || key.length !== 16) {
        MemoryManager.constantTimeDelay(2);
        return false;
      }
      
      if (!Buffer.isBuffer(data)) {
        MemoryManager.constantTimeDelay(2);
        return false;
      }
      
      if (!Buffer.isBuffer(expectedMac)) {
        MemoryManager.constantTimeDelay(2);
        return false;
      }
      
      const calculatedMac = this.calculate(key, data);
      const truncatedMac = calculatedMac.slice(0, expectedMac.length);
      
      if (truncatedMac.length !== expectedMac.length) {
        MemoryManager.constantTimeDelay(2);
        return false;
      }
      
      return MemoryManager.timingSafeEqual(truncatedMac, expectedMac);
    } catch (error) {
      MemoryManager.constantTimeDelay(2);
      return false;
    }
  }
  
  /**
   * Verify CMAC with detailed error information
   * @param {Buffer} key - 16-byte AES key used for CMAC
   * @param {Buffer} data - Data that was authenticated
   * @param {Buffer} expectedMac - Expected CMAC value to verify against
   * @returns {Object} Detailed verification result
   */
  static verifyDetailed(key, data, expectedMac) {
    try {
      if (!Buffer.isBuffer(key) || key.length !== 16) {
        throw new ValidationError('Key must be a 16-byte Buffer', 'key', key?.length, 16);
      }
      
      if (!Buffer.isBuffer(data)) {
        throw new ValidationError('Data must be a Buffer', 'data', typeof data, 'Buffer');
      }
      
      if (!Buffer.isBuffer(expectedMac)) {
        throw new ValidationError('Expected MAC must be a Buffer', 'expectedMac', typeof expectedMac, 'Buffer');
      }
      
      const calculatedMac = this.calculate(key, data);
      const truncatedMac = calculatedMac.slice(0, expectedMac.length);
      
      const isValid = MemoryManager.timingSafeEqual(truncatedMac, expectedMac);
      
      return {
        isValid,
        calculatedMac: calculatedMac.toString('hex').toUpperCase(),
        expectedMac: expectedMac.toString('hex').toUpperCase(),
        truncatedMac: truncatedMac.toString('hex').toUpperCase(),
        lengthMatch: truncatedMac.length === expectedMac.length
      };
    } catch (error) {
      MemoryManager.constantTimeDelay(2);
      
      if (error instanceof ValidationError) {
        throw error;
      }
      
      throw new SecurityError(`CMAC detailed verification failed: ${error.message}`, 'CMAC_VERIFICATION_FAILURE');
    }
  }
}

module.exports = CMAC;
