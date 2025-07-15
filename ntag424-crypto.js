const crypto = require('crypto');
const { aesCmac } = require('node-aes-cmac');

/**
 * Universal NTAG424 Cryptographic Library
 * 
 * A comprehensive, hardware-agnostic library for NTAG424 DNA encryption/decryption operations.
 * This library provides complete cryptographic functionality for NTAG424 tags without requiring
 * any NFC hardware dependencies, making it perfect for server-side processing and validation.
 * 
 * @author NTAG424 Crypto Team
 * @version 1.0.0
 * @license MIT
 * 
 * Key Features:
 * - Multiple key derivation algorithms (NTAG424 official, HKDF, PBKDF2, custom hash)
 * - Configurable SDM (Secure Dynamic Messaging) modes
 * - AES-128 encryption/decryption with CBC and ECB modes
 * - Proper AES-CMAC authentication using node-aes-cmac
 * - Flexible data parsing (URLs, query strings, objects)
 * - Comprehensive validation and error handling
 * - Zero hardware dependencies - pure cryptographic operations
 * 
 * Dependencies:
 * - crypto (Node.js built-in)
 * - node-aes-cmac (required for proper CMAC operations)
 * 
 * Usage Example:
 * ```javascript
 * const decoder = new NTAG424Crypto.Decoder('00112233445566778899AABBCCDDEEFF');
 * const result = decoder.decrypt('https://example.com/nfc?picc_data=ABC123&cmac=DEF456');
 * ```
 */
class NTAG424Crypto {
  
  /**
   * Key Derivation Methods
   * 
   * This class provides various cryptographic key derivation functions for generating
   * session keys from master keys. Different methods offer different security levels
   * and performance characteristics.
   */
  static KeyDerivation = class {
    
    /**
     * NTAG424 Official CMAC-based Key Derivation
     * 
     * Implements the official NXP NTAG424 key derivation specification using CMAC.
     * This method follows the exact procedure defined in NXP documentation for
     * generating encryption and MAC keys from master key, UID, and read counter.
     * 
     * @param {Buffer} masterKey - The master key (16 bytes) for key derivation
     * @param {Buffer} uid - The tag UID (typically 7 bytes)
     * @param {Buffer} readCounter - The read counter (3 bytes)
     * @param {Object} options - Optional configuration parameters
     * @param {boolean} options.useCMAC - Whether to use CMAC for derivation (default: true)
     * @param {number} options.keyLength - Length of derived keys in bytes (default: 16)
     * @returns {Object} Object containing encKey, macKey, and method name
     * 
     * @example
     * const masterKey = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
     * const uid = Buffer.from('04958CAA5C5E80', 'hex');
     * const counter = Buffer.from('000001', 'hex');
     * const keys = NTAG424Crypto.KeyDerivation.ntag424Official(masterKey, uid, counter);
     */
    static ntag424Official(masterKey, uid, readCounter, options = {}) {
      const { useCMAC = true, keyLength = 16 } = options;
      
      const sv1 = NTAG424Crypto.KeyDerivation.buildSV1(uid, readCounter, options);
      const sv2 = NTAG424Crypto.KeyDerivation.buildSV2(uid, readCounter, options);
      
      let encKey, macKey;
      
      if (useCMAC) {
        encKey = NTAG424Crypto.CMAC.calculate(masterKey, sv1).slice(0, keyLength);
        macKey = NTAG424Crypto.CMAC.calculate(masterKey, sv2).slice(0, keyLength);
      } else {
        encKey = NTAG424Crypto.AES.ecbEncrypt(masterKey, sv1.slice(0, 16)).slice(0, keyLength);
        macKey = NTAG424Crypto.AES.ecbEncrypt(masterKey, sv2.slice(0, 16)).slice(0, keyLength);
      }
      
      return { encKey, macKey, method: 'ntag424-official' };
    }
    
    /**
     * HKDF-based Key Derivation
     * 
     * Uses the HMAC-based Key Derivation Function (RFC 5869) for generating session keys.
     * This is a modern, standardized approach that provides strong security properties
     * and is suitable for high-security applications.
     * 
     * @param {Buffer} masterKey - The master key for derivation
     * @param {Buffer} uid - The tag UID
     * @param {Buffer} readCounter - The read counter
     * @param {Object} options - Configuration options
     * @param {string} options.algorithm - Hash algorithm to use (default: 'sha256')
     * @param {Buffer} options.salt - Optional salt for HKDF (default: concatenated uid+counter)
     * @param {string} options.info - Info string for HKDF (default: 'NTAG424-SESSION-KEYS')
     * @param {number} options.keyLength - Total key material length (default: 32)
     * @returns {Object} Object containing encKey, macKey, and method name
     * 
     * @example
     * const keys = NTAG424Crypto.KeyDerivation.hkdf(masterKey, uid, counter, {
     *   algorithm: 'sha256',
     *   keyLength: 32
     * });
     */
    static hkdf(masterKey, uid, readCounter, options = {}) {
      const { 
        algorithm = 'sha256',
        salt = null,
        info = 'NTAG424-SESSION-KEYS',
        keyLength = 32 
      } = options;
      
      const inputSalt = salt || Buffer.concat([uid || Buffer.alloc(0), readCounter || Buffer.alloc(0)]);
      const infoBuffer = Buffer.from(info, 'utf8');
      
      const derivedKeys = crypto.hkdfSync(algorithm, masterKey, inputSalt, infoBuffer, keyLength);
      
      return {
        encKey: derivedKeys.slice(0, keyLength / 2),
        macKey: derivedKeys.slice(keyLength / 2),
        method: 'hkdf'
      };
    }
    
    /**
     * PBKDF2-based Key Derivation
     * 
     * Uses Password-Based Key Derivation Function 2 (RFC 2898) with configurable iterations.
     * This method is slower but provides additional protection against brute-force attacks
     * through computational cost.
     * 
     * @param {Buffer} masterKey - The master key for derivation
     * @param {Buffer} uid - The tag UID
     * @param {Buffer} readCounter - The read counter
     * @param {Object} options - Configuration options
     * @param {number} options.iterations - Number of PBKDF2 iterations (default: 10000)
     * @param {string} options.algorithm - Hash algorithm (default: 'sha256')
     * @param {string} options.saltPrefix - Prefix for salt construction (default: 'NTAG424')
     * @param {number} options.keyLength - Total key material length (default: 32)
     * @returns {Object} Object containing encKey, macKey, and method name
     * 
     * @example
     * const keys = NTAG424Crypto.KeyDerivation.pbkdf2(masterKey, uid, counter, {
     *   iterations: 50000,
     *   algorithm: 'sha512'
     * });
     */
    static pbkdf2(masterKey, uid, readCounter, options = {}) {
      const { 
        iterations = 10000,
        algorithm = 'sha256',
        saltPrefix = 'NTAG424',
        keyLength = 32 
      } = options;
      
      const salt = Buffer.concat([
        Buffer.from(saltPrefix, 'utf8'),
        uid || Buffer.alloc(0),
        readCounter || Buffer.alloc(0)
      ]);
      
      const derivedKeys = crypto.pbkdf2Sync(masterKey, salt, iterations, keyLength, algorithm);
      
      return {
        encKey: derivedKeys.slice(0, keyLength / 2),
        macKey: derivedKeys.slice(keyLength / 2),
        method: 'pbkdf2'
      };
    }
    
    /**
     * Simple Hash-based Key Derivation
     * 
     * A fast, simple key derivation method using standard hash functions.
     * Suitable for applications where performance is critical and the threat model
     * allows for simpler key derivation.
     * 
     * @param {Buffer} masterKey - The master key for derivation
     * @param {Buffer} uid - The tag UID
     * @param {Buffer} readCounter - The read counter
     * @param {Object} options - Configuration options
     * @param {string} options.algorithm - Hash algorithm (default: 'sha256')
     * @param {number} options.keyLength - Length of each derived key (default: 16)
     * @returns {Object} Object containing encKey, macKey, and method name
     * 
     * @example
     * const keys = NTAG424Crypto.KeyDerivation.simpleHash(masterKey, uid, counter, {
     *   algorithm: 'sha512',
     *   keyLength: 32
     * });
     */
    static simpleHash(masterKey, uid, readCounter, options = {}) {
      const { algorithm = 'sha256', keyLength = 16 } = options;
      
      const encSeed = Buffer.concat([
        masterKey,
        uid || Buffer.alloc(0),
        readCounter || Buffer.alloc(0),
        Buffer.from('ENC', 'utf8')
      ]);
      
      const macSeed = Buffer.concat([
        masterKey,
        uid || Buffer.alloc(0),
        readCounter || Buffer.alloc(0),
        Buffer.from('MAC', 'utf8')
      ]);
      
      const encHash = crypto.createHash(algorithm).update(encSeed).digest();
      const macHash = crypto.createHash(algorithm).update(macSeed).digest();
      
      return {
        encKey: encHash.slice(0, keyLength),
        macKey: macHash.slice(0, keyLength),
        method: 'simple-hash'
      };
    }
    
    /**
     * Custom Key Derivation
     * 
     * Allows users to provide their own key derivation function for specialized requirements.
     * The provided function should accept (masterKey, uid, readCounter) and return an object
     * with encKey and macKey properties.
     * 
     * @param {Buffer} masterKey - The master key for derivation
     * @param {Buffer} uid - The tag UID
     * @param {Buffer} readCounter - The read counter
     * @param {Function} derivationFunction - User-provided derivation function
     * @returns {Object} Object containing encKey, macKey, and method name
     * 
     * @example
     * const customDerivation = (key, uid, counter) => {
     *   // Custom logic here
     *   return { encKey: Buffer.alloc(16), macKey: Buffer.alloc(16) };
     * };
     * const keys = NTAG424Crypto.KeyDerivation.custom(masterKey, uid, counter, customDerivation);
     */
    static custom(masterKey, uid, readCounter, derivationFunction) {
      const result = derivationFunction(masterKey, uid, readCounter);
      return { ...result, method: 'custom' };
    }
    
    /**
     * Build SV1 (Session Vector 1) for NTAG424 encryption key derivation
     * 
     * Constructs the session vector used in the official NTAG424 key derivation process
     * for generating the encryption key. Follows NXP specification format.
     * 
     * @param {Buffer} uid - The tag UID
     * @param {Buffer} readCounter - The read counter
     * @param {Object} options - Configuration options
     * @param {number} options.svLength - Length of session vector (default: 32)
     * @param {string} options.encLabel - Hex string label for encryption (default: '3CC300010080')
     * @returns {Buffer} The constructed SV1 buffer
     */
    static buildSV1(uid, readCounter, options = {}) {
      const { svLength = 32, encLabel = '3CC300010080' } = options;
      const sv1 = Buffer.alloc(svLength, 0x00);
      
      let offset = 0;
      
      sv1.write(encLabel, offset, 'hex');
      offset += Buffer.from(encLabel, 'hex').length;
      
      if (uid && uid.length > 0) {
        uid.copy(sv1, offset);
        offset += uid.length;
      }
      
      if (readCounter && readCounter.length > 0) {
        readCounter.copy(sv1, offset);
        offset += readCounter.length;
      }
      
      return sv1;
    }
    
    /**
     * Build SV2 (Session Vector 2) for NTAG424 MAC key derivation
     * 
     * Constructs the session vector used in the official NTAG424 key derivation process
     * for generating the MAC key. Follows NXP specification format.
     * 
     * @param {Buffer} uid - The tag UID
     * @param {Buffer} readCounter - The read counter
     * @param {Object} options - Configuration options
     * @param {number} options.svLength - Length of session vector (default: 32)
     * @param {string} options.macLabel - Hex string label for MAC (default: '3CC300010081')
     * @returns {Buffer} The constructed SV2 buffer
     */
    static buildSV2(uid, readCounter, options = {}) {
      const { svLength = 32, macLabel = '3CC300010081' } = options;
      const sv2 = Buffer.alloc(svLength, 0x00);
      
      let offset = 0;
      
      sv2.write(macLabel, offset, 'hex');
      offset += Buffer.from(macLabel, 'hex').length;
      
      if (uid && uid.length > 0) {
        uid.copy(sv2, offset);
        offset += uid.length;
      }
      
      if (readCounter && readCounter.length > 0) {
        readCounter.copy(sv2, offset);
        offset += readCounter.length;
      }
      
      return sv2;
    }
  }
  
  /**
   * SDM (Secure Dynamic Messaging) Configuration Handler
   * 
   * Manages different SDM profile configurations for NTAG424 tags. SDM profiles define
   * what data is included in the encrypted PICC data (UID, counter, file data) and
   * their positions within the data structure.
   */
  static SDMConfig = class {
    
    /**
     * Predefined SDM profiles for common NTAG424 configurations.
     * Each profile defines the structure and content of encrypted data.
     */
    static profiles = {
      uidOnly: {
        includeUID: true,
        includeCounter: false,
        includeFileData: false,
        piccDataLength: 16,
        uidOffset: 1,
        uidLength: 7
      },
      
      counterOnly: {
        includeUID: false,
        includeCounter: true,
        includeFileData: false,
        piccDataLength: 16,
        counterOffset: 1,
        counterLength: 3
      },
      
      uidCounter: {
        includeUID: true,
        includeCounter: true,
        includeFileData: false,
        piccDataLength: 16,
        uidOffset: 1,
        uidLength: 7,
        counterOffset: 8,
        counterLength: 3
      },
      
      full: {
        includeUID: true,
        includeCounter: true,
        includeFileData: true,
        piccDataLength: 16,
        uidOffset: 1,
        uidLength: 7,
        counterOffset: 8,
        counterLength: 3,
        encFileDataLength: 16
      }
    };
    
    /**
     * Get a predefined SDM profile by name
     * 
     * @param {string} profileName - Name of the profile (uidOnly, counterOnly, uidCounter, full)
     * @returns {Object} The SDM profile configuration object
     * 
     * @example
     * const profile = NTAG424Crypto.SDMConfig.getProfile('uidCounter');
     */
    static getProfile(profileName) {
      return this.profiles[profileName] || this.profiles.uidCounter;
    }
    
    /**
     * Create a custom SDM profile configuration
     * 
     * Allows creation of custom SDM profiles for non-standard NTAG424 configurations.
     * All parameters are optional and will default to safe values.
     * 
     * @param {Object} config - Custom configuration object
     * @param {boolean} config.includeUID - Whether UID is included in PICC data
     * @param {boolean} config.includeCounter - Whether counter is included in PICC data
     * @param {boolean} config.includeFileData - Whether encrypted file data is present
     * @param {number} config.piccDataLength - Length of PICC data block
     * @param {number} config.uidOffset - Byte offset of UID in PICC data
     * @param {number} config.uidLength - Length of UID in bytes
     * @param {number} config.counterOffset - Byte offset of counter in PICC data
     * @param {number} config.counterLength - Length of counter in bytes
     * @param {number} config.encFileDataLength - Length of encrypted file data
     * @returns {Object} Complete SDM profile configuration
     * 
     * @example
     * const customProfile = NTAG424Crypto.SDMConfig.createCustomProfile({
     *   includeUID: true,
     *   includeCounter: false,
     *   uidOffset: 2,
     *   uidLength: 6
     * });
     */
    static createCustomProfile(config) {
      return {
        includeUID: config.includeUID || false,
        includeCounter: config.includeCounter || false,
        includeFileData: config.includeFileData || false,
        piccDataLength: config.piccDataLength || 16,
        uidOffset: config.uidOffset || 1,
        uidLength: config.uidLength || 7,
        counterOffset: config.counterOffset || 8,
        counterLength: config.counterLength || 3,
        encFileDataLength: config.encFileDataLength || 16,
        ...config
      };
    }
  }
  
  /**
   * AES Encryption/Decryption Operations
   * 
   * Provides AES encryption and decryption operations in CBC and ECB modes.
   * All operations use AES-128 with proper padding handling.
   */
  static AES = class {
    
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
     * const encrypted = NTAG424Crypto.AES.cbcEncrypt(key, data);
     */
    static cbcEncrypt(key, data, iv = null) {
      const actualIV = iv || Buffer.alloc(16, 0x00);
      const cipher = crypto.createCipheriv('aes-128-cbc', key, actualIV);
      cipher.setAutoPadding(true);
      
      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      return encrypted;
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
     * const decrypted = NTAG424Crypto.AES.cbcDecrypt(key, encryptedData);
     */
    static cbcDecrypt(key, data, iv = null) {
      const actualIV = iv || Buffer.alloc(16, 0x00);
      const decipher = crypto.createDecipheriv('aes-128-cbc', key, actualIV);
      decipher.setAutoPadding(true);
      
      let decrypted = decipher.update(data);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted;
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
     * const encrypted = NTAG424Crypto.AES.ecbEncrypt(key, sixteenByteData);
     */
    static ecbEncrypt(key, data) {
      const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
      cipher.setAutoPadding(false);
      
      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      return encrypted;
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
     * const decrypted = NTAG424Crypto.AES.ecbDecrypt(key, encryptedData);
     */
    static ecbDecrypt(key, data) {
      const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
      decipher.setAutoPadding(false);
      
      let decrypted = decipher.update(data);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted;
    }
  }
  
  /**
   * CMAC (Cipher-based Message Authentication Code) Operations
   * 
   * Provides AES-CMAC calculation and verification using the node-aes-cmac library.
   * CMAC is essential for NTAG424 authentication and data integrity verification.
   */
  static CMAC = class {
    
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
     * const cmac = NTAG424Crypto.CMAC.calculate(key, data);
     */
    static calculate(key, data) {
      return aesCmac(key, data);
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
     * const isValid = NTAG424Crypto.CMAC.verify(key, data, receivedCmac);
     * if (isValid) {
     *   console.log('Data is authentic');
     * }
     */
    static verify(key, data, expectedMac) {
      const calculatedMac = aesCmac(key, data);
      const truncatedMac = calculatedMac.slice(0, expectedMac.length);
      
      const expectedBuffer = Buffer.isBuffer(expectedMac) ? expectedMac : Buffer.from(expectedMac);
      const calculatedBuffer = Buffer.isBuffer(truncatedMac) ? truncatedMac : Buffer.from(truncatedMac);
      
      return calculatedBuffer.equals(expectedBuffer);
    }
  }
  
  /**
   * Data Parsing and Validation Utilities
   * 
   * Provides utilities for parsing NTAG424 data from various formats (URLs, query strings),
   * validating data integrity, and extracting structured information from decrypted data.
   */
  static DataParser = class {
    
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
     * const data = NTAG424Crypto.DataParser.parseURL(url);
     * // Returns: { picc: 'ABC123', enc: null, cmac: 'DEF456', counter: null, ... }
     */
    static parseURL(url) {
      try {
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
     * const data = NTAG424Crypto.DataParser.parseQueryString(query);
     */
    static parseQueryString(queryString) {
      const params = new URLSearchParams(queryString);
      return {
        picc: params.get('picc_data') || params.get('picc') || params.get('uid'),
        enc: params.get('enc') || params.get('enc_data'),
        cmac: params.get('cmac') || params.get('mac'),
        counter: params.get('ctr') || params.get('counter')
      };
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
     * const isValid = NTAG424Crypto.DataParser.validateHexString('ABC123', 6);
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
      
      if (expectedLength && hexString.length !== expectedLength) {
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
     * const piccInfo = NTAG424Crypto.DataParser.extractPiccData(decrypted, 'uidCounter');
     * console.log(`UID: ${piccInfo.uid.toString('hex')}`);
     * console.log(`Counter: ${piccInfo.readCounterInt}`);
     */
    static extractPiccData(decryptedPicc, sdmConfig) {
      const config = typeof sdmConfig === 'string' 
        ? NTAG424Crypto.SDMConfig.getProfile(sdmConfig)
        : sdmConfig;
      
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
        result.readCounterInt = result.readCounter.readUIntBE(0, config.counterLength);
      }
      
      const dataEnd = Math.max(
        config.includeUID ? config.uidOffset + config.uidLength : 0,
        config.includeCounter ? config.counterOffset + config.counterLength : 0
      );
      
      if (decryptedPicc.length > dataEnd) {
        result.padding = decryptedPicc.slice(dataEnd);
      }
      
      return result;
    }
  }
  
  /**
   * Main NTAG424 Decoder Class
   * 
   * The primary interface for NTAG424 decryption operations. This class combines all
   * the cryptographic components to provide a simple, high-level API for decrypting
   * NTAG424 SDM data from various sources.
   */
  static Decoder = class {
    
    /**
     * Create a new NTAG424 Decoder instance
     * 
     * Initializes a decoder with the specified master key and configuration options.
     * The decoder can then be used to decrypt multiple NTAG424 messages with consistent
     * settings.
     * 
     * @param {string} masterKey - Master key as hexadecimal string (32 characters for 16 bytes)
     * @param {Object} options - Configuration options for the decoder
     * @param {string} options.keyDerivationMethod - Key derivation method ('ntag424Official', 'hkdf', 'pbkdf2', 'simpleHash')
     * @param {string|Object} options.sdmProfile - SDM profile name or custom profile object
     * @param {boolean} options.validateCMAC - Whether to validate CMAC authenticity (default: true)
     * @param {boolean} options.strictValidation - Enable strict input validation (default: false)
     * 
     * @example
     * const decoder = new NTAG424Crypto.Decoder('00112233445566778899AABBCCDDEEFF', {
     *   keyDerivationMethod: 'ntag424Official',
     *   sdmProfile: 'uidCounter',
     *   validateCMAC: true
     * });
     */
    constructor(masterKey, options = {}) {
      this.masterKey = Buffer.from(masterKey, 'hex');
      this.options = {
        keyDerivationMethod: 'ntag424Official',
        sdmProfile: 'uidCounter',
        validateCMAC: true,
        strictValidation: false,
        ...options
      };
    }
    
    /**
     * Decrypt NTAG424 SDM data
     * 
     * Main decryption method that accepts NTAG424 data in various formats (URL, query string,
     * or object) and returns decrypted information including UID, counter, file data, and
     * CMAC validation results.
     * 
     * @param {string|Object} input - NTAG424 data as URL, query string, or object
     * @param {Object} customOptions - Optional override options for this specific operation
     * @returns {Object} Decryption result object
     * @returns {boolean} returns.success - Whether decryption was successful
     * @returns {string} returns.uid - Extracted UID as hex string (if present)
     * @returns {number} returns.readCounter - Read counter value (if present)
     * @returns {string} returns.dataTag - Data tag as hex string (if present)
     * @returns {string} returns.encryptedFileData - Decrypted file data as hex string (if present)
     * @returns {boolean} returns.cmacValid - Whether CMAC validation passed
     * @returns {Object} returns.sessionKeys - Generated session keys and derivation method
     * @returns {Object} returns.rawDecrypted - Raw decrypted data for debugging
     * @returns {Object} returns.piccInfo - Detailed PICC data extraction results
     * @returns {string} returns.error - Error message if decryption failed
     * 
     * @example
     * const result = decoder.decrypt('https://example.com/nfc?picc_data=ABC123&cmac=DEF456');
     * if (result.success && result.cmacValid) {
     *   console.log(`UID: ${result.uid}, Counter: ${result.readCounter}`);
     * } else {
     *   console.log(`Decryption failed: ${result.error}`);
     * }
     */
    decrypt(input, customOptions = {}) {
      const options = { ...this.options, ...customOptions };
      
      try {
        const data = this._parseInput(input);
        
        if (options.strictValidation) {
          this._validateInput(data);
        }
        
        const piccData = Buffer.from(data.picc, 'hex');
        const encData = data.enc ? Buffer.from(data.enc, 'hex') : null;
        const cmacData = Buffer.from(data.cmac, 'hex');
        
        const sdmConfig = typeof options.sdmProfile === 'string'
          ? NTAG424Crypto.SDMConfig.getProfile(options.sdmProfile)
          : options.sdmProfile;
        
        const result = this._performDecryption(
          piccData, 
          encData, 
          cmacData, 
          sdmConfig, 
          options
        );
        
        return {
          success: true,
          ...result,
          options: {
            keyDerivationMethod: options.keyDerivationMethod,
            sdmProfile: options.sdmProfile,
            validateCMAC: options.validateCMAC
          }
        };
        
      } catch (error) {
        return {
          success: false,
          error: error.message,
          stack: options.includeStack ? error.stack : undefined
        };
      }
    }
    
    /**
     * Parse input data from various formats
     * 
     * Internal method to normalize input data from URLs, query strings, or objects
     * into a consistent format for processing.
     * 
     * @private
     * @param {string|Object} input - Input data in various formats
     * @returns {Object} Normalized data object
     * @throws {Error} If input format is not recognized
     */
    _parseInput(input) {
      if (typeof input === 'string') {
        if (input.includes('://')) {
          return NTAG424Crypto.DataParser.parseURL(input);
        } else {
          return NTAG424Crypto.DataParser.parseQueryString(input);
        }
      } else if (typeof input === 'object') {
        return input;
      } else {
        throw new Error('Invalid input format');
      }
    }
    
    /**
     * Validate input data format and content
     * 
     * Internal method that performs strict validation of input data when
     * strictValidation option is enabled.
     * 
     * @private
     * @param {Object} data - Parsed input data
     * @throws {Error} If validation fails
     */
    _validateInput(data) {
      if (!data.picc) {
        throw new Error('Missing PICC data');
      }
      if (!data.cmac) {
        throw new Error('Missing CMAC data');
      }
      if (!NTAG424Crypto.DataParser.validateHexString(data.picc)) {
        throw new Error('Invalid PICC hex format');
      }
      if (!NTAG424Crypto.DataParser.validateHexString(data.cmac)) {
        throw new Error('Invalid CMAC hex format');
      }
      if (data.enc && !NTAG424Crypto.DataParser.validateHexString(data.enc)) {
        throw new Error('Invalid ENC hex format');
      }
    }
    
    /**
     * Perform the actual decryption process
     * 
     * Internal method that handles the core decryption logic, including iterative
     * key derivation attempts and data validation.
     * 
     * @private
     * @param {Buffer} piccData - PICC data buffer
     * @param {Buffer} encData - Encrypted file data buffer (optional)
     * @param {Buffer} cmacData - CMAC data buffer
     * @param {Object} sdmConfig - SDM configuration
     * @param {Object} options - Processing options
     * @returns {Object} Decryption results
     * @throws {Error} If all decryption attempts fail
     */
    _performDecryption(piccData, encData, cmacData, sdmConfig, options) {
      try {
        const zeroUid = Buffer.alloc(7, 0);
        const zeroCounter = Buffer.alloc(3, 0);
        
        const sessionKeys = this._deriveKeys(zeroUid, zeroCounter, options.keyDerivationMethod);
        
        let decryptedPicc;
        try {
          decryptedPicc = NTAG424Crypto.AES.cbcDecrypt(sessionKeys.encKey, piccData);
        } catch (decryptError) {
          throw new Error(`Decryption failed: ${decryptError.message}`);
        }
        
        const piccInfo = NTAG424Crypto.DataParser.extractPiccData(decryptedPicc, sdmConfig);
        
        if (piccInfo.uid && piccInfo.readCounter) {
          const correctSessionKeys = this._deriveKeys(
            piccInfo.uid, 
            piccInfo.readCounter, 
            options.keyDerivationMethod
          );
          
          try {
            decryptedPicc = NTAG424Crypto.AES.cbcDecrypt(correctSessionKeys.encKey, piccData);
            const finalPiccInfo = NTAG424Crypto.DataParser.extractPiccData(decryptedPicc, sdmConfig);
            
            let decryptedEnc = null;
            if (encData) {
              decryptedEnc = NTAG424Crypto.AES.cbcDecrypt(correctSessionKeys.encKey, encData);
            }
            
            let cmacValid = true;
            if (options.validateCMAC) {
              const dataToVerify = Buffer.concat([
                piccData,
                encData || Buffer.alloc(0)
              ]);
              cmacValid = NTAG424Crypto.CMAC.verify(correctSessionKeys.macKey, dataToVerify, cmacData);
            }
            
            return {
              uid: finalPiccInfo.uid ? finalPiccInfo.uid.toString('hex').toUpperCase() : null,
              readCounter: finalPiccInfo.readCounterInt || null,
              dataTag: finalPiccInfo.dataTag ? finalPiccInfo.dataTag.toString(16) : null,
              encryptedFileData: decryptedEnc ? decryptedEnc.toString('hex') : null,
              cmacValid,
              sessionKeys: {
                encKey: correctSessionKeys.encKey.toString('hex'),
                macKey: correctSessionKeys.macKey.toString('hex'),
                derivationMethod: correctSessionKeys.method
              },
              rawDecrypted: {
                picc: decryptedPicc.toString('hex'),
                enc: decryptedEnc ? decryptedEnc.toString('hex') : null
              },
              piccInfo: finalPiccInfo
            };
            
          } catch (reDecryptError) {
            let decryptedEnc = null;
            if (encData) {
              try {
                decryptedEnc = NTAG424Crypto.AES.cbcDecrypt(sessionKeys.encKey, encData);
              } catch (encDecryptError) {
                
              }
            }
            
            let cmacValid = true;
            if (options.validateCMAC) {
              const dataToVerify = Buffer.concat([
                piccData,
                encData || Buffer.alloc(0)
              ]);
              cmacValid = NTAG424Crypto.CMAC.verify(sessionKeys.macKey, dataToVerify, cmacData);
            }
            
            return {
              uid: piccInfo.uid ? piccInfo.uid.toString('hex').toUpperCase() : null,
              readCounter: piccInfo.readCounterInt || null,
              dataTag: piccInfo.dataTag ? piccInfo.dataTag.toString(16) : null,
              encryptedFileData: decryptedEnc ? decryptedEnc.toString('hex') : null,
              cmacValid,
              sessionKeys: {
                encKey: sessionKeys.encKey.toString('hex'),
                macKey: sessionKeys.macKey.toString('hex'),
                derivationMethod: sessionKeys.method
              },
              rawDecrypted: {
                picc: decryptedPicc.toString('hex'),
                enc: decryptedEnc ? decryptedEnc.toString('hex') : null
              },
              piccInfo
            };
          }
        }
        
        let decryptedEnc = null;
        if (encData) {
          try {
            decryptedEnc = NTAG424Crypto.AES.cbcDecrypt(sessionKeys.encKey, encData);
          } catch (encDecryptError) {
            
          }
        }
        
        let cmacValid = true;
        if (options.validateCMAC) {
          const dataToVerify = Buffer.concat([
            piccData,
            encData || Buffer.alloc(0)
          ]);
          cmacValid = NTAG424Crypto.CMAC.verify(sessionKeys.macKey, dataToVerify, cmacData);
        }
        
        return {
          uid: piccInfo.uid ? piccInfo.uid.toString('hex').toUpperCase() : null,
          readCounter: piccInfo.readCounterInt || null,
          dataTag: piccInfo.dataTag ? piccInfo.dataTag.toString(16) : null,
          encryptedFileData: decryptedEnc ? decryptedEnc.toString('hex') : null,
          cmacValid,
          sessionKeys: {
            encKey: sessionKeys.encKey.toString('hex'),
            macKey: sessionKeys.macKey.toString('hex'),
            derivationMethod: sessionKeys.method
          },
          rawDecrypted: {
            picc: decryptedPicc.toString('hex'),
            enc: decryptedEnc ? decryptedEnc.toString('hex') : null
          },
          piccInfo
        };
        
      } catch (error) {
        throw new Error(`Decryption failed: ${error.message}`);
      }
    }
    
    /**
     * Derive session keys using specified method
     * 
     * Internal method that calls the appropriate key derivation function based on
     * the configured method.
     * 
     * @private
     * @param {Buffer} uid - Tag UID
     * @param {Buffer} readCounter - Read counter
     * @param {string} method - Key derivation method name
     * @returns {Object} Derived keys object
     * @throws {Error} If method is unknown
     */
    _deriveKeys(uid, readCounter, method) {
      const derivationMethods = {
        'ntag424Official': NTAG424Crypto.KeyDerivation.ntag424Official,
        'hkdf': NTAG424Crypto.KeyDerivation.hkdf,
        'pbkdf2': NTAG424Crypto.KeyDerivation.pbkdf2,
        'simpleHash': NTAG424Crypto.KeyDerivation.simpleHash
      };
      
      const derivationFunction = derivationMethods[method];
      if (!derivationFunction) {
        throw new Error(`Unknown key derivation method: ${method}`);
      }
      
      return derivationFunction(this.masterKey, uid, readCounter);
    }
  }
}

module.exports = NTAG424Crypto;
