/**
 * Universal NTAG424 Cryptographic Library
 * 
 * A focused, production-ready library for NTAG424 DNA encryption/decryption operations.
 * This library provides complete cryptographic functionality for NTAG424 tags without 
 * hardware dependencies, designed for real-world applications with known data.
 * 
 * @author Serdar Tepekule
 * @version 2.0.0
 * @license MIT
 * 
 * Key Features:
 * - Fixed SDM profile validation bug
 * - Structured error handling with context
 * - Enhanced security with memory management
 * - Multiple key derivation algorithms (NTAG424 official, HKDF, PBKDF2, custom hash)
 * - Configurable SDM (Secure Dynamic Messaging) modes
 * - AES-128 encryption/decryption with CBC and ECB modes
 * - Proper AES-CMAC authentication using node-aes-cmac
 * - Flexible data parsing and output formats
 * - Secure master key generation
 * - URL and query string generation
 * - Zero hardware dependencies
 * 
 * Dependencies:
 * - crypto (Node.js built-in)
 * - node-aes-cmac (required for proper CMAC operations)
 * 
 * Usage Example:
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
  
  /**
   * Key Derivation Methods
   * 
   * Provides various cryptographic key derivation functions for generating
   * session keys from master keys.
   */
  static KeyDerivation = KeyDerivation;

  /**
   * NTAG424 Encryption Helper Methods
   * 
   * Simple helper methods for encrypting data and generating various output formats.
   * Includes secure master key generation and URL formatting.
   */
  static Encoder = Encoder;
  
  /**
   * SDM (Secure Dynamic Messaging) Configuration Handler
   * 
   * Manages different SDM profile configurations for NTAG424 tags.
   */
  static SDMConfig = SDMConfig;
  
  /**
   * AES Encryption/Decryption Operations
   * 
   * Provides AES encryption and decryption operations in CBC and ECB modes.
   */
  static AES = AES;
  
  /**
   * CMAC (Cipher-based Message Authentication Code) Operations
   * 
   * Provides AES-CMAC calculation and verification using the node-aes-cmac library.
   */
  static CMAC = CMAC;
  
  /**
   * Data Parsing and Validation Utilities
   * 
   * Provides utilities for parsing NTAG424 data from various formats.
   */
  static DataParser = DataParser;
  
  /**
   * Main NTAG424 Decoder Class
   * 
   * The primary interface for NTAG424 decryption operations.
   */
  static Decoder = Decoder;
  
  /**
   * Get library version information
   * 
   * @returns {Object} Version and build information
   */
  static getVersionInfo() {
    return {
      version: '2.0.0',
      name: 'ntag424-crypto',
      author: 'Serdar Tepekule',
      license: 'MIT',
      description: 'NTAG424 cryptographic library with fixed SDM validation and enhanced security',
      features: [
        'Fixed SDM profile validation bug',
        'Structured error handling',
        'Enhanced security with memory management',
        'Multiple key derivation methods',
        'Configurable SDM profiles',
        'Production-ready performance',
        'Zero hardware dependencies'
      ],
      modules: {
        KeyDerivation: 'Key derivation algorithms',
        Encoder: 'Data encryption and formatting',
        Decoder: 'Data decryption engine',
        AES: 'AES encryption/decryption',
        CMAC: 'CMAC authentication',
        SDMConfig: 'SDM profile management',
        DataParser: 'Data parsing utilities'
      }
    };
  }
  
  /**
   * Validate library dependencies
   * 
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
