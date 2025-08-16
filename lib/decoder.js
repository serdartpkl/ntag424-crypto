/**
 * NTAG424 Decoder with Security and Error Handling
 * 
 * Decrypts NTAG424 SDM data with security and performance improvements
 */

const AES = require('./aes');
const CMAC = require('./cmac');
const KeyDerivation = require('./key-derivation');
const DataParser = require('./data-parser');
const SDMConfig = require('./sdm-config');
const { SecureBuffer, MemoryManager } = require('./secure-memory');
const { ValidationError, DecryptionError, ErrorHelper } = require('./error-types');

/**
 * NTAG424 Decoder
 */
class Decoder {
  
  /**
   * Create a new NTAG424 Decoder instance
   * @param {string} masterKey - Master key as hexadecimal string (32 characters for 16 bytes)
   * @param {Object} options - Configuration options for the decoder
   */
  constructor(masterKey, options = {}) {
    try {
      this._validateMasterKey(masterKey);
      
      this.memoryManager = new MemoryManager();
      this.masterKeyBuffer = this.memoryManager.createSecureBuffer(16);
      Buffer.from(masterKey, 'hex').copy(this.masterKeyBuffer.data);
      
      this.options = {
        keyDerivationMethod: 'ntag424Official',
        sdmProfile: 'uidCounter',
        validateCMAC: true,
        strictValidation: false,
        timingAttackProtection: true,
        ...options
      };
      
      this._validateOptions();
    } catch (error) {
      throw new ValidationError(
        `Decoder initialization failed: ${error.message}`,
        'constructor',
        { masterKey: masterKey ? '[REDACTED]' : null, options }
      );
    }
  }

  /**
   * Decrypt NTAG424 SDM data
   * @param {string|Object} input - NTAG424 data as URL, query string, or object
   * @param {Object} customOptions - Optional override options for this specific operation
   * @returns {Object} Decryption result object
   */
  decrypt(input, customOptions = {}) {
    const startTime = Date.now();
    const context = ErrorHelper.createContext('decrypt', input, customOptions);

    try {
      const options = { ...this.options, ...customOptions };
      
      const data = this._parseInput(input, context);
      
      const profile = typeof options.sdmProfile === 'string'
        ? SDMConfig.getProfile(options.sdmProfile)
        : options.sdmProfile;
      
      SDMConfig.validateOperationWithProfile('decrypt', profile, data);
      
      const result = this._performSecureDecryption(data, profile, options, context);
      
      const duration = Date.now() - startTime;
      
      return {
        success: true,
        ...result,
        performance: {
          duration
        },
        context,
        options: {
          keyDerivationMethod: options.keyDerivationMethod,
          sdmProfile: options.sdmProfile,
          validateCMAC: options.validateCMAC
        }
      };
      
    } catch (error) {
      const duration = Date.now() - startTime;
      
      if (this.options.timingAttackProtection) {
        MemoryManager.constantTimeDelay(Math.max(1, 5 - duration));
      }
      
      return {
        success: false,
        error: error.message,
        errorCode: error.code,
        errorType: error.name,
        context,
        performance: {
          duration: Date.now() - startTime
        }
      };
    }
  }

  /**
   * Perform the actual decryption process with security measures
   * @param {Object} data - Parsed input data
   * @param {Object} profile - SDM profile
   * @param {Object} options - Decryption options
   * @param {Object} context - Operation context
   * @returns {Object} Decryption result
   */
  _performSecureDecryption(data, profile, options, context) {
    const piccData = this._hexToBuffer(data.picc, 'PICC data');
    const encData = data.enc ? this._hexToBuffer(data.enc, 'ENC data') : null;
    const cmacData = this._hexToBuffer(data.cmac, 'CMAC data');
    
    try {
      // Use zero vectors for key derivation (NTAG424 standard)
      const zeroUID = Buffer.alloc(7, 0);
      const zeroCounter = Buffer.alloc(3, 0);
      
      // Derive session keys
      const sessionKeys = this._deriveKeys(
        this.masterKeyBuffer.data,
        zeroUID,
        zeroCounter,
        options.keyDerivationMethod
      );
      
      // Decrypt PICC data
      const decryptedPicc = AES.cbcDecrypt(sessionKeys.encKey, piccData);
      
      // Extract PICC information
      const piccInfo = this._extractPiccData(decryptedPicc, profile);
      
      // Validate decryption
      if (!this._isValidDecryption(decryptedPicc, piccInfo)) {
        throw new DecryptionError(
          'Invalid decrypted data structure',
          'validation',
          { 
            dataTag: piccInfo.dataTag,
            expectedDataTag: 0xC7,
            piccLength: decryptedPicc.length
          }
        );
      }
      
      // Decrypt file data if present
      let decryptedEnc = null;
      if (encData) {
        if (!profile.includeFileData) {
          throw new DecryptionError(
            `Profile '${profile.name}' does not support encrypted file data`,
            'fileDecryption',
            { profile: profile.name }
          );
        }
        
        try {
          decryptedEnc = AES.cbcDecrypt(sessionKeys.encKey, encData);
        } catch (encDecryptError) {
          throw new DecryptionError(
            `File data decryption failed: ${encDecryptError.message}`,
            'fileDecryption',
            { originalError: encDecryptError.message }
          );
        }
      }
      
      // Verify CMAC
      let cmacValid = true;
      if (options.validateCMAC) {
        try {
          const dataToVerify = Buffer.concat([
            piccData,
            encData || Buffer.alloc(0)
          ]);
          
          const calculatedCmac = CMAC.calculate(sessionKeys.macKey, dataToVerify);
          cmacValid = MemoryManager.timingSafeEqual(
            calculatedCmac.slice(0, cmacData.length),
            cmacData
          );
        } catch (cmacError) {
          throw new DecryptionError(
            `CMAC verification failed: ${cmacError.message}`,
            'cmacVerification',
            { originalError: cmacError.message }
          );
        }
      }
      
      return {
        uid: piccInfo.uid ? piccInfo.uid.toString('hex').toUpperCase() : null,
        readCounter: piccInfo.readCounterInt !== null && piccInfo.readCounterInt !== undefined ? piccInfo.readCounterInt : null,
        dataTag: piccInfo.dataTag !== null && piccInfo.dataTag !== undefined ? piccInfo.dataTag.toString(16).toUpperCase() : null,
        encryptedFileData: this._extractFileData(decryptedEnc),
        cmacValid,
        sessionKeys: {
          encKey: sessionKeys.encKey.toString('hex').toUpperCase(),
          macKey: sessionKeys.macKey.toString('hex').toUpperCase(),
          derivationMethod: sessionKeys.method
        },
        rawDecrypted: {
          picc: decryptedPicc.toString('hex').toUpperCase(),
          enc: decryptedEnc ? decryptedEnc.toString('hex').toUpperCase() : null
        },
        piccInfo,
        metadata: {
          timestamp: new Date().toISOString(),
          profileUsed: profile.name || 'custom'
        }
      };
      
    } catch (error) {
      if (error instanceof DecryptionError) {
        throw error;
      }
      throw new DecryptionError(
        `Zero vector decryption failed: ${error.message}`,
        'decryption',
        { originalError: error.message }
      );
    }
  }

  /**
   * Validate if decrypted data has proper NTAG424 structure
   * @param {Buffer} decryptedPicc - Decrypted PICC data
   * @param {Object} piccInfo - Extracted PICC information
   * @returns {boolean} True if valid
   */
  _isValidDecryption(decryptedPicc, piccInfo) {
    try {
      if (piccInfo.dataTag !== 0xC7) {
        return false;
      }
      
      if (!decryptedPicc || decryptedPicc.length < 11) {
        return false;
      }
      
      if (piccInfo.uid && piccInfo.uid[0] !== 0x04) {
        return false;
      }
      
      if (piccInfo.readCounterInt !== null && 
          (piccInfo.readCounterInt < 0 || piccInfo.readCounterInt > 16777215)) {
        return false;
      }
      
      return true;
      
    } catch (error) {
      return false;
    }
  }

  /**
   * Extract file data from decrypted buffer
   * @param {Buffer} decryptedEnc - Decrypted file data
   * @returns {string|null} Extracted file data
   */
  _extractFileData(decryptedEnc) {
    if (!decryptedEnc || !Buffer.isBuffer(decryptedEnc)) {
      return null;
    }
    
    try {
      const utf8String = decryptedEnc.toString('utf8').replace(/\0+$/, '');
      return utf8String.length > 0 ? utf8String : null;
    } catch (error) {
      try {
        return decryptedEnc.toString('hex').replace(/(00)+$/, '');
      } catch (hexError) {
        return null;
      }
    }
  }

  /**
   * Extract structured data from decrypted PICC data
   * @param {Buffer} decryptedPicc - Decrypted PICC data
   * @param {Object} profile - SDM profile
   * @returns {Object} Extracted PICC information
   */
  _extractPiccData(decryptedPicc, profile) {
    return DataParser.extractPiccData(decryptedPicc, profile);
  }

  /**
   * Convert hex string to buffer with proper validation
   * @param {string} hexString - Hex string to convert
   * @param {string} fieldName - Field name for error messages
   * @returns {Buffer} Converted buffer
   */
  _hexToBuffer(hexString, fieldName) {
    try {
      if (!hexString || typeof hexString !== 'string') {
        throw new ValidationError(
          `${fieldName} must be a non-empty string`,
          fieldName,
          typeof hexString
        );
      }
      
      if (!DataParser.validateHexString(hexString)) {
        throw new ValidationError(
          `${fieldName} contains invalid hex characters`,
          fieldName,
          hexString
        );
      }
      
      if (hexString.length % 2 !== 0) {
        throw new ValidationError(
          `${fieldName} hex string must have even length`,
          fieldName,
          `${hexString.length} characters`
        );
      }
      
      return Buffer.from(hexString, 'hex');
    } catch (error) {
      throw new DecryptionError(
        `Failed to convert ${fieldName} to Buffer: ${error.message}`,
        'hexToBuffer',
        { fieldName, hexString: hexString?.substring(0, 20) + '...' }
      );
    }
  }

  /**
   * Parse input data from various formats
   * @param {string|Object} input - Input data
   * @param {Object} context - Operation context
   * @returns {Object} Parsed data
   */
  _parseInput(input, context) {
    try {
      if (typeof input === 'string') {
        if (input.includes('://')) {
          return DataParser.parseURL(input);
        } else {
          return DataParser.parseQueryString(input);
        }
      } else if (typeof input === 'object' && input !== null) {
        return input;
      } else {
        throw new ValidationError(
          'Invalid input format',
          'input',
          typeof input
        );
      }
    } catch (error) {
      throw new DecryptionError(
        `Input parsing failed: ${error.message}`,
        'parseInput',
        { inputType: typeof input }
      );
    }
  }

  /**
   * Derive session keys using specified method
   * @param {Buffer} masterKey - Master key
   * @param {Buffer} uid - UID
   * @param {Buffer} readCounter - Read counter
   * @param {string} method - Key derivation method
   * @returns {Object} Session keys
   */
  _deriveKeys(masterKey, uid, readCounter, method) {
    const derivationMethods = {
      'ntag424Official': KeyDerivation.ntag424Official,
      'hkdf': KeyDerivation.hkdf,
      'pbkdf2': KeyDerivation.pbkdf2,
      'simpleHash': KeyDerivation.simpleHash
    };
    
    const derivationFunction = derivationMethods[method];
    if (!derivationFunction) {
      throw new DecryptionError(
        `Unknown key derivation method: ${method}`,
        'keyDerivation'
      );
    }
    
    const result = derivationFunction(masterKey, uid, readCounter);
    
    return {
      encKey: Buffer.isBuffer(result.encKey) ? result.encKey : Buffer.from(result.encKey),
      macKey: Buffer.isBuffer(result.macKey) ? result.macKey : Buffer.from(result.macKey),
      method: result.method || method
    };
  }

  /**
   * Validate master key format
   * @param {string} masterKey - Master key to validate
   */
  _validateMasterKey(masterKey) {
    if (!masterKey || typeof masterKey !== 'string' || masterKey.length !== 32) {
      throw new ValidationError(
        'Master key must be a 32-character hex string',
        'masterKey',
        masterKey ? `${masterKey.length} characters` : 'null'
      );
    }
    
    if (!/^[0-9A-Fa-f]+$/.test(masterKey)) {
      throw new ValidationError(
        'Master key contains invalid hex characters',
        'masterKey',
        masterKey
      );
    }
  }

  /**
   * Validate decoder options
   */
  _validateOptions() {
    const validMethods = ['ntag424Official', 'hkdf', 'pbkdf2', 'simpleHash'];
    if (!validMethods.includes(this.options.keyDerivationMethod)) {
      throw new ValidationError(
        `Invalid key derivation method: ${this.options.keyDerivationMethod}`,
        'keyDerivationMethod',
        this.options.keyDerivationMethod
      );
    }
    
    if (typeof this.options.sdmProfile === 'string') {
      const validProfiles = SDMConfig.getAvailableProfiles();
      if (!validProfiles.includes(this.options.sdmProfile)) {
        throw new ValidationError(
          `Invalid SDM profile: ${this.options.sdmProfile}`,
          'sdmProfile',
          this.options.sdmProfile
        );
      }
    } else if (typeof this.options.sdmProfile === 'object') {
      const validation = SDMConfig.validateProfile(this.options.sdmProfile);
      if (!validation.isValid) {
        throw new ValidationError(
          `Invalid SDM profile: ${validation.errors.join(', ')}`,
          'sdmProfile',
          this.options.sdmProfile
        );
      }
    }
  }

  /**
   * Cleanup resources
   */
  destroy() {
    if (this.memoryManager) {
      this.memoryManager.clearAll();
    }
  }
}

module.exports = Decoder;
