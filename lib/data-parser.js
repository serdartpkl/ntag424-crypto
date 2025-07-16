const { ValidationError, DecryptionError } = require('./error-types');

/**
 * Data Parsing and Validation Utilities
 * 
 * Provides utilities for parsing NTAG424 data from various formats (URLs, query strings),
 * validating data integrity, and extracting structured information from decrypted data.
 */
class DataParser {
  
  /**
   * Parse NTAG424 data from URL
   * 
   * @param {string} url - Complete URL containing NTAG424 parameters
   * @returns {Object} Parsed data object with picc, enc, cmac, and counter fields
   */
  static parseURL(url) {
    try {
      if (!url || typeof url !== 'string') {
        throw new ValidationError('URL must be a non-empty string', 'url', typeof url, 'string');
      }
      
      const urlObj = new URL(url);
      const params = urlObj.searchParams;
      
      return {
        picc: params.get('picc_data') || params.get('picc') || params.get('uid'),
        enc: params.get('enc') || params.get('enc_data') || params.get('encdata'),
        cmac: params.get('cmac') || params.get('mac'),
        counter: params.get('ctr') || params.get('counter'),
        originalUrl: url,
        baseUrl: `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`
      };
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new ValidationError(`Invalid URL format: ${error.message}`, 'url', url);
    }
  }
  
  /**
   * Parse NTAG424 data from query string
   * 
   * @param {string} queryString - Query string containing NTAG424 parameters
   * @returns {Object} Parsed data object with picc, enc, cmac, and counter fields
   */
  static parseQueryString(queryString) {
    try {
      if (!queryString || typeof queryString !== 'string') {
        throw new ValidationError('Query string must be a non-empty string', 'queryString', typeof queryString, 'string');
      }
      
      const params = new URLSearchParams(queryString);
      return {
        picc: params.get('picc_data') || params.get('picc') || params.get('uid'),
        enc: params.get('enc') || params.get('enc_data'),
        cmac: params.get('cmac') || params.get('mac'),
        counter: params.get('ctr') || params.get('counter')
      };
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new ValidationError(`Invalid query string format: ${error.message}`, 'queryString', queryString);
    }
  }
  
  /**
   * Validate hexadecimal string format
   * 
   * @param {string} hexString - String to validate
   * @param {number} expectedLength - Expected length in characters (optional)
   * @returns {boolean} True if valid hex string, false otherwise
   */
  static validateHexString(hexString, expectedLength = null) {
    if (!hexString || typeof hexString !== 'string') {
      return false;
    }
    
    const hexPattern = /^[0-9A-Fa-f]+$/;
    if (!hexPattern.test(hexString)) {
      return false;
    }
    
    if (expectedLength !== null && hexString.length !== expectedLength) {
      return false;
    }
    
    return true;
  }
  
  /**
   * Extract structured data from decrypted PICC data
   * 
   * @param {Buffer} decryptedPicc - Decrypted PICC data buffer
   * @param {Object|string} sdmConfig - SDM configuration object or profile name
   * @returns {Object} Extracted data with dataTag, uid, readCounter, etc.
   */
  static extractPiccData(decryptedPicc, sdmConfig) {
    try {
      if (!Buffer.isBuffer(decryptedPicc)) {
        throw new ValidationError('Decrypted PICC data must be a Buffer', 'decryptedPicc', typeof decryptedPicc, 'Buffer');
      }
      
      let config;
      if (typeof sdmConfig === 'string') {
        const SDMConfig = require('./sdm-config');
        config = SDMConfig.getProfile(sdmConfig);
      } else {
        config = sdmConfig;
      }
      
      if (!config) {
        throw new ValidationError('Invalid SDM configuration', 'sdmConfig', typeof sdmConfig);
      }
      
      const result = {
        dataTag: null,
        uid: null,
        readCounter: null,
        readCounterInt: null,
        padding: null,
        raw: decryptedPicc
      };
      
      if (decryptedPicc.length > 0) {
        result.dataTag = decryptedPicc[0];
      }
      
      if (config.includeUID && decryptedPicc.length >= config.uidOffset + config.uidLength) {
        result.uid = decryptedPicc.slice(config.uidOffset, config.uidOffset + config.uidLength);
      }
      
      if (config.includeCounter && decryptedPicc.length >= config.counterOffset + config.counterLength) {
        result.readCounter = decryptedPicc.slice(config.counterOffset, config.counterOffset + config.counterLength);
        try {
          if (result.readCounter.length >= 3) {
            result.readCounterInt = result.readCounter.readUIntBE(0, 3);
          } else if (result.readCounter.length === 2) {
            result.readCounterInt = result.readCounter.readUIntBE(0, 2);
          } else if (result.readCounter.length === 1) {
            result.readCounterInt = result.readCounter[0];
          } else {
            result.readCounterInt = 0;
          }
        } catch (error) {
          result.readCounterInt = 0;
          for (let i = 0; i < result.readCounter.length; i++) {
            result.readCounterInt = (result.readCounterInt << 8) + result.readCounter[i];
          }
        }
      }
      
      const dataEnd = Math.max(
        config.includeUID ? config.uidOffset + config.uidLength : 0,
        config.includeCounter ? config.counterOffset + config.counterLength : 0
      );
      
      if (decryptedPicc.length > dataEnd) {
        result.padding = decryptedPicc.slice(dataEnd);
      }
      
      return result;
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new DecryptionError(`PICC data extraction failed: ${error.message}`, 'extractPiccData');
    }
  }
  
  /**
   * Validate parsed NTAG424 data structure
   * 
   * @param {Object} data - Parsed NTAG424 data object
   * @param {Object} options - Validation options
   * @returns {Object} Validation result with isValid flag and errors array
   */
  static validateParsedData(data, options = {}) {
    const {
      requirePicc = true,
      requireCmac = true,
      strictHex = false
    } = options;
    
    const errors = [];
    
    if (!data || typeof data !== 'object') {
      return { isValid: false, errors: ['Data must be an object'] };
    }
    
    if (requirePicc && !data.picc) {
      errors.push('Missing PICC data');
    }
    
    if (requireCmac && !data.cmac) {
      errors.push('Missing CMAC data');
    }
    
    if (strictHex) {
      if (data.picc && !this.validateHexString(data.picc)) {
        errors.push('Invalid PICC hex format');
      }
      if (data.cmac && !this.validateHexString(data.cmac)) {
        errors.push('Invalid CMAC hex format');
      }
      if (data.enc && !this.validateHexString(data.enc)) {
        errors.push('Invalid ENC hex format');
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }
  
  /**
   * Convert hex string to Buffer with validation
   * 
   * @param {string} hexString - Hex string to convert
   * @param {string} fieldName - Name of the field for error messages
   * @returns {Buffer} Converted Buffer
   */
  static hexToBuffer(hexString, fieldName = 'data') {
    try {
      if (!hexString || typeof hexString !== 'string') {
        throw new ValidationError(`${fieldName} must be a non-empty string`, fieldName, typeof hexString, 'string');
      }
      
      if (!this.validateHexString(hexString)) {
        throw new ValidationError(`${fieldName} contains invalid hex characters`, fieldName, hexString);
      }
      
      if (hexString.length % 2 !== 0) {
        throw new ValidationError(`${fieldName} hex string must have even length`, fieldName, `${hexString.length} characters`, 'even length');
      }
      
      return Buffer.from(hexString, 'hex');
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new ValidationError(`Failed to convert ${fieldName} to Buffer: ${error.message}`, fieldName, hexString);
    }
  }
  
  /**
   * Clean and normalize hex string
   * 
   * @param {string} hexString - Hex string to clean
   * @returns {string} Cleaned hex string
   */
  static cleanHexString(hexString) {
    if (!hexString || typeof hexString !== 'string') {
      throw new ValidationError('Hex string must be a non-empty string', 'hexString', typeof hexString, 'string');
    }
    
    const cleaned = hexString.replace(/\s/g, '').toUpperCase();
    
    if (!this.validateHexString(cleaned)) {
      throw new ValidationError('Invalid hex string format', 'hexString', cleaned);
    }
    
    return cleaned;
  }
  
  /**
   * Validate UID format
   * 
   * @param {string} uid - UID string to validate
   * @returns {boolean} True if valid UID format
   */
  static validateUID(uid) {
    if (!uid || typeof uid !== 'string') {
      return false;
    }
    
    if (uid.length !== 14) {
      return false;
    }
    
    if (!this.validateHexString(uid)) {
      return false;
    }
    
    if (!uid.toUpperCase().startsWith('04')) {
      return false;
    }
    
    return true;
  }
  
  /**
   * Validate counter value
   * 
   * @param {number} counter - Counter value to validate
   * @returns {boolean} True if valid counter
   */
  static validateCounter(counter) {
    if (typeof counter !== 'number') {
      return false;
    }
    
    if (!Number.isInteger(counter)) {
      return false;
    }
    
    if (counter < 0 || counter > 0xFFFFFF) {
      return false;
    }
    
    return true;
  }
  
  /**
   * Parse and validate complete NTAG424 input
   * 
   * @param {string|Object} input - Input to parse and validate
   * @param {Object} options - Validation options
   * @returns {Object} Parsed and validated data
   */
  static parseAndValidate(input, options = {}) {
    let parsed;
    
    try {
      if (typeof input === 'string') {
        if (input.includes('://')) {
          parsed = this.parseURL(input);
        } else {
          parsed = this.parseQueryString(input);
        }
      } else if (typeof input === 'object' && input !== null) {
        parsed = input;
      } else {
        throw new ValidationError('Invalid input format', 'input', typeof input);
      }
      
      const validation = this.validateParsedData(parsed, options);
      if (!validation.isValid) {
        throw new ValidationError(
          `Data validation failed: ${validation.errors.join(', ')}`,
          'parsedData',
          parsed
        );
      }
      
      return parsed;
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new ValidationError(`Input parsing and validation failed: ${error.message}`, 'input', input);
    }
  }
}

module.exports = DataParser;
