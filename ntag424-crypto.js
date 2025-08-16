/**
 * Universal NTAG424 Cryptographic Library
 * 
 * Production-ready library for NTAG424 DNA encryption/decryption operations.
 * 
 * @author Serdar Tepekule
 * @version 2.0.1
 * @license MIT
 * 
 * @example
 * ```javascript
 * const NTAG424Crypto = require('./ntag424-crypto');
 * 
 * // Generate secure master key
 * const masterKey = NTAG424Crypto.Encoder.generateMasterKey();
 * 
 * // Encrypt data (file data requires 'full' profile)
 * const encrypted = NTAG424Crypto.Encoder.encrypt(masterKey, '04AABBCCDDEE80', 42, 'Secret!', {
 *   sdmProfile: 'full'
 * });
 * 
 * // Generate URL
 * const url = NTAG424Crypto.Encoder.generateURL(encrypted, 'https://mysite.com/nfc');
 * 
 * // Decrypt data
 * const decoder = new NTAG424Crypto.Decoder(masterKey, { sdmProfile: 'full' });
 * const result = decoder.decrypt(url);
 * ```
 */

const KeyDerivation = require('./lib/key-derivation');
const AES = require('./lib/aes');
const CMAC = require('./lib/cmac');
const SDMConfig = require('./lib/sdm-config');
const DataParser = require('./lib/data-parser');
const Encoder = require('./lib/encoder');
const Decoder = require('./lib/decoder');

/**
 * Main NTAG424Crypto class that combines all modules
 */
class NTAG424Crypto {
  
  /** @type {KeyDerivation} Key derivation algorithms */
  static KeyDerivation = KeyDerivation;

  /** @type {Encoder} Data encryption and formatting */
  static Encoder = Encoder;
  
  /** @type {SDMConfig} SDM profile management */
  static SDMConfig = SDMConfig;
  
  /** @type {AES} AES encryption/decryption */
  static AES = AES;
  
  /** @type {CMAC} CMAC authentication */
  static CMAC = CMAC;
  
  /** @type {DataParser} Data parsing utilities */
  static DataParser = DataParser;
  
  /** @type {Decoder} Data decryption engine */
  static Decoder = Decoder;
  
  /**
   * Get library version information
   * @returns {Object} Version and build information
   */
  static getVersionInfo() {
    return {
      version: '2.0.1',
      name: 'ntag424-crypto',
      author: 'Serdar Tepekule',
      license: 'MIT',
      description: 'Production-ready Node.js library for NTAG424 DNA encryption and decryption operations.'
    };
  }
  
  /**
   * Validate library dependencies
   * @returns {Object} Dependency validation results
   */
  static validateDependencies() {
    const results = {
      crypto: false,
      aesCmac: false,
      allValid: false,
      missing: []
    };
    
    try {
      require('crypto');
      results.crypto = true;
    } catch (error) {
      results.missing.push('crypto (Node.js built-in)');
    }
    
    try {
      require('node-aes-cmac');
      results.aesCmac = true;
    } catch (error) {
      results.missing.push('node-aes-cmac');
    }
    
    results.allValid = results.crypto && results.aesCmac;
    
    return results;
  }
}

module.exports = NTAG424Crypto;
