const SDMConfig = require('./sdm-config');

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
   * Extracts NTAG424 parameters from a complete URL containing SDM data.
   * Supports various parameter naming conventions used by different implementations.
   * 
   * @param {string} url - Complete URL containing NTAG424 parameters
   * @returns {Object} Parsed data object with picc, enc, cmac, and counter fields
   * @throws {Error} If URL format is invalid
   * 
   * @example
   * const url = 'https://example.com/nfc?picc_data=ABC123&cmac=DEF456';
   * const data = DataParser.parseURL(url);
   * // Returns: { picc: 'ABC123', enc: null, cmac: 'DEF456', counter: null, ... }
   */
  static parseURL(url) {
    try {
      if (!url || typeof url !== 'string') {
        throw new Error('URL must be a non-empty string');
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
      throw new Error(`Invalid URL format: ${error.message}`);
    }
  }
  
  /**
   * Parse NTAG424 data from query string
   * 
   * Extracts NTAG424 parameters from a query string without requiring a full URL.
   * 
   * @param {string} queryString - Query string containing NTAG424 parameters
   * @returns {Object} Parsed data object with picc, enc, cmac, and counter fields
   * 
   * @example
   * const query = 'picc_data=ABC123&cmac=DEF456';
   * const data = DataParser.parseQueryString(query);
   */
  static parseQueryString(queryString) {
    try {
      if (!queryString || typeof queryString !== 'string') {
        throw new Error('Query string must be a non-empty string');
      }
      
      const params = new URLSearchParams(queryString);
      return {
        picc: params.get('picc_data') || params.get('picc') || params.get('uid'),
        enc: params.get('enc') || params.get('enc_data'),
        cmac: params.get('cmac') || params.get('mac'),
        counter: params.get('ctr') || params.get('counter')
      };
    } catch (error) {
      throw new Error(`Invalid query string format: ${error.message}`);
    }
  }
  
  /**
   * Validate hexadecimal string format
   * 
   * Checks if a string contains valid hexadecimal characters and optionally
   * validates the length against expected values.
   * 
   * @param {string} hexString - String to validate
   * @param {number} expectedLength - Expected length in characters (optional)
   * @returns {boolean} True if valid hex string, false otherwise
   * 
   * @example
   * const isValid = DataParser.validateHexString('ABC123', 6);
   * // Returns: true
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
   * Parses decrypted PICC data according to the specified SDM configuration to extract
   * UID, read counter, and other structured information. Handles different data layouts
   * based on the SDM profile.
   * 
   * @param {Buffer} decryptedPicc - Decrypted PICC data buffer
   * @param {Object|string} sdmConfig - SDM configuration object or profile name
   * @returns {Object} Extracted data with dataTag, uid, readCounter, etc.
   * 
   * @example
   * const piccInfo = DataParser.extractPiccData(decrypted, 'uidCounter');
   * console.log(`UID: ${piccInfo.uid.toString('hex')}`);
   * console.log(`Counter: ${piccInfo.readCounterInt}`);
   */
  static extractPiccData(decryptedPicc, sdmConfig) {
    try {
      if (!Buffer.isBuffer(decryptedPicc)) {
        throw new Error('Decrypted PICC data must be a Buffer');
      }
      
      const config = typeof sdmConfig === 'string' 
        ? SDMConfig.getProfile(sdmConfig)
        : sdmConfig;
      
      if (!config) {
        throw new Error('Invalid SDM configuration');
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
      throw new Error(`PICC data extraction failed: ${error.message}`);
    }
  }
  
  /**
   * Validate parsed NTAG424 data structure
   * 
   * Checks if the parsed data contains required fields and valid formats.
   * 
   * @param {Object} data - Parsed NTAG424 data object
   * @param {Object} options - Validation options
   * @param {boolean} options.requirePicc - Whether PICC data is required (default: true)
   * @param {boolean} options.requireCmac - Whether CMAC is required (default: true)
   * @param {boolean} options.strictHex - Whether to perform strict hex validation (default: false)
   * @returns {Object} Validation result with isValid flag and errors array
   * 
   * @example
   * const validation = DataParser.validateParsedData(parsedData, { strictHex: true });
   * if (!validation.isValid) {
   *   console.error('Data validation errors:', validation.errors);
   * }
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
   * Safely converts a hex string to a Buffer with proper error handling.
   * 
   * @param {string} hexString - Hex string to convert
   * @param {string} fieldName - Name of the field for error messages
   * @returns {Buffer} Converted Buffer
   * @throws {Error} If conversion fails
   * 
   * @example
   * const buffer = DataParser.hexToBuffer('ABC123', 'PICC data');
   */
  static hexToBuffer(hexString, fieldName = 'data') {
    try {
      if (!hexString || typeof hexString !== 'string') {
        throw new Error(`${fieldName} must be a non-empty string`);
      }
      
      if (!this.validateHexString(hexString)) {
        throw new Error(`${fieldName} contains invalid hex characters`);
      }
      
      if (hexString.length % 2 !== 0) {
        throw new Error(`${fieldName} hex string must have even length`);
      }
      
      return Buffer.from(hexString, 'hex');
    } catch (error) {
      throw new Error(`Failed to convert ${fieldName} to Buffer: ${error.message}`);
    }
  }
  
  /**
   * Clean and normalize hex string
   * 
   * Removes whitespace, converts to uppercase, and validates hex string format.
   * 
   * @param {string} hexString - Hex string to clean
   * @returns {string} Cleaned hex string
   * @throws {Error} If string is invalid
   * 
   * @example
   * const cleaned = DataParser.cleanHexString('  abc 123  ');
   * // Returns: 'ABC123'
   */
  static cleanHexString(hexString) {
    if (!hexString || typeof hexString !== 'string') {
      throw new Error('Hex string must be a non-empty string');
    }
    
    const cleaned = hexString.replace(/\s/g, '').toUpperCase();
    
    if (!this.validateHexString(cleaned)) {
      throw new Error('Invalid hex string format');
    }
    
    return cleaned;
  }
}

module.exports = DataParser;
