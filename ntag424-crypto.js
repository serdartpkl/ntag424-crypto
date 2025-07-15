/**
 * Universal NTAG424 Cryptographic Library
 * 
 * A focused, production-ready library for NTAG424 DNA encryption/decryption operations.
 * This library provides complete cryptographic functionality for NTAG424 tags without 
 * hardware dependencies, designed for real-world applications with known data.
 * 
 * @author Serdar Tepekule
 * @version 1.0.0
 * @license MIT
 * 
 * Key Features:
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
 * // Encrypt data
 * const encrypted = NTAG424Crypto.Encoder.encrypt(masterKey, '04AABBCCDDEE80', 42);
 * 
 * // Generate URL
 * const url = NTAG424Crypto.Encoder.generateURL(encrypted, 'https://mysite.com/nfc');
 * 
 * // Decrypt data
 * const decoder = new NTAG424Crypto.Decoder(masterKey);
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
      author: 'NTAG424 Crypto Team',
      license: 'MIT',
      description: 'Focused NTAG424 cryptographic library for real-world applications',
      features: [
        'Secure master key generation',
        'Multiple output formats (URL, query string, object)',
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
  
  /**
   * Quick validation helper
   * 
   * @param {string} masterKey - Master key as hex string
   * @param {string|Object} input - NTAG424 data to validate
   * @param {Object} options - Optional configuration
   * @returns {Object} Quick validation result
   */
  static quickValidate(masterKey, input, options = {}) {
    try {
      const decoder = new Decoder(masterKey, options);
      const result = decoder.decrypt(input);
      
      return {
        valid: result.success && result.cmacValid,
        success: result.success,
        cmacValid: result.cmacValid,
        uid: result.uid,
        counter: result.readCounter,
        error: result.error
      };
    } catch (error) {
      return {
        valid: false,
        success: false,
        error: error.message
      };
    }
  }
  
  /**
   * Performance benchmark helper
   * 
   * @param {Object} options - Benchmark options
   * @returns {Object} Benchmark results
   */
  static benchmark(options = {}) {
    const {
      iterations = 1000,
      masterKey = null,
      uid = '04AABBCCDDEE80',
      counter = 42
    } = options;
    
    try {
      const testMasterKey = masterKey || Encoder.generateMasterKey();
      const testData = Encoder.encrypt(testMasterKey, uid, counter);
      
      const decoder = new Decoder(testMasterKey);
      const testInput = {
        picc: testData.encryptedData.picc,
        cmac: testData.encryptedData.cmac
      };
      
      const startTime = Date.now();
      let successCount = 0;
      
      for (let i = 0; i < iterations; i++) {
        const result = decoder.decrypt(testInput);
        if (result.success) successCount++;
      }
      
      const totalTime = Date.now() - startTime;
      
      return {
        iterations,
        totalTime,
        avgDecryptTime: totalTime / iterations,
        throughput: Math.round(iterations / (totalTime / 1000)),
        successRate: (successCount / iterations) * 100,
        testData: {
          masterKey: testMasterKey,
          uid: uid,
          counter: counter
        }
      };
    } catch (error) {
      return {
        error: error.message
      };
    }
  }
  
  /**
   * Create a complete NTAG424 solution
   * 
   * @param {Object} config - Configuration for the solution
   * @returns {Object} Complete solution with encoder, decoder, and utilities
   */
  static createSolution(config = {}) {
    const {
      masterKey = null,
      baseURL = 'https://example.com/nfc',
      sdmProfile = 'uidCounter',
      keyDerivationMethod = 'ntag424Official'
    } = config;
    
    const actualMasterKey = masterKey || Encoder.generateMasterKey();
    
    return {
      masterKey: actualMasterKey,
      
      encrypt(uid, counter, fileData = null) {
        return Encoder.encrypt(actualMasterKey, uid, counter, fileData, {
          sdmProfile,
          keyDerivationMethod
        });
      },
      
      generateURL(encryptedData) {
        return Encoder.generateURL(encryptedData, baseURL);
      },
      
      generateQueryString(encryptedData) {
        return Encoder.generateQueryString(encryptedData);
      },
      
      decrypt(input) {
        const decoder = new Decoder(actualMasterKey, {
          sdmProfile,
          keyDerivationMethod
        });
        return decoder.decrypt(input);
      },
      
      validate(input) {
        return NTAG424Crypto.quickValidate(actualMasterKey, input, {
          sdmProfile,
          keyDerivationMethod
        });
      },
      
      config: {
        baseURL,
        sdmProfile,
        keyDerivationMethod
      }
    };
  }
}

module.exports = NTAG424Crypto;
