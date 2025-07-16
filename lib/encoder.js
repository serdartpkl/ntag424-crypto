const AES = require('./aes');
const CMAC = require('./cmac');
const KeyDerivation = require('./key-derivation');
const SDMConfig = require('./sdm-config');
const { SecureBuffer, MemoryManager } = require('./secure-memory');
const { ValidationError, EncryptionError } = require('./error-types');

/**
 * NTAG424 Encoder with Proper SDM Profile Validation
 * 
 * Provides secure encryption with comprehensive validation and memory management
 */
class Encoder {
  
  /**
   * Encrypt NTAG424 data with comprehensive validation
   * 
   * @param {string} masterKey - Master key as hex string (32 characters)
   * @param {string|Buffer} uid - Tag UID (7 bytes as hex string or Buffer)
   * @param {number|Buffer} scanCount - Scan counter (number or 3-byte Buffer)
   * @param {string|Buffer} fileData - Optional file data to encrypt
   * @param {Object} options - Optional configuration
   * @returns {Object} Object containing original data and encrypted components
   */
  static encrypt(masterKey, uid, scanCount, fileData = null, options = {}) {
    const memoryManager = new MemoryManager();
    
    try {
      const {
        keyDerivationMethod = 'ntag424Official',
        sdmProfile = fileData ? 'full' : 'uidCounter'
      } = options;
      
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
      
      const uidBuffer = this._validateAndConvertUID(uid);
      const counterBuffer = this._validateAndConvertCounter(scanCount);
      
      const profile = typeof sdmProfile === 'string' 
        ? SDMConfig.getProfile(sdmProfile)
        : sdmProfile;
      
      if (!profile) {
        throw new ValidationError(
          'Invalid SDM profile',
          'sdmProfile',
          sdmProfile
        );
      }
      
      SDMConfig.validateOperationWithProfile('encrypt', profile, {
        uid: uidBuffer,
        counter: counterBuffer,
        fileData: fileData
      });
      
      const masterKeyBuffer = memoryManager.createSecureBuffer(16);
      Buffer.from(masterKey, 'hex').copy(masterKeyBuffer.data);
      
      const zeroUID = Buffer.alloc(7, 0);
      const zeroCounter = Buffer.alloc(3, 0);
      
      const piccData = this._buildPiccData(uidBuffer, counterBuffer, profile);
      
      const sessionKeys = this._deriveKeys(
        masterKeyBuffer.data,
        zeroUID,
        zeroCounter,
        keyDerivationMethod
      );
      
      const encryptedPicc = AES.cbcEncrypt(sessionKeys.encKey, piccData);
      
      let encryptedFile = null;
      let cmacData = encryptedPicc;
      
      if (fileData) {
        if (!profile.includeFileData) {
          throw new ValidationError(
            `Profile '${profile.name}' does not support file data encryption. Use 'full' profile instead.`,
            'sdmProfile',
            profile.name
          );
        }
        
        const fileBuffer = this._prepareFileData(fileData);
        encryptedFile = AES.cbcEncrypt(sessionKeys.encKey, fileBuffer);
        cmacData = Buffer.concat([encryptedPicc, encryptedFile]);
      }
      
      const cmac = CMAC.calculate(sessionKeys.macKey, cmacData).slice(0, 8);
      
      const result = {
        originalData: {
          uid: uidBuffer.toString('hex').toUpperCase(),
          scanCount: this._counterToNumber(counterBuffer),
          masterKey: '[REDACTED]',
          keyDerivationMethod,
          sdmProfile: profile.name || 'custom'
        },
        encryptedData: {
          picc: encryptedPicc.toString('hex').toUpperCase(),
          cmac: cmac.toString('hex').toUpperCase()
        },
        metadata: {
          timestamp: new Date().toISOString(),
          profileUsed: profile.name || 'custom',
          hasFileData: !!fileData
        }
      };
      
      if (fileData) {
        result.originalData.fileData = fileData.toString();
        result.encryptedData.enc = encryptedFile.toString('hex').toUpperCase();
      }
      
      return result;
      
    } catch (error) {
      if (!(error instanceof ValidationError || error instanceof EncryptionError)) {
        throw new EncryptionError(
          `Encryption failed: ${error.message}`,
          'encrypt',
          { originalError: error.message }
        );
      }
      throw error;
    } finally {
      memoryManager.clearAll();
    }
  }
  
  /**
   * Generate URL format from encrypted data
   * 
   * @param {Object} encryptedData - Result from encrypt() method
   * @param {string} baseURL - Base URL for the NFC tag
   * @returns {string} Complete URL with encrypted parameters
   */
  static generateURL(encryptedData, baseURL = 'https://example.com/nfc') {
    try {
      if (!encryptedData || !encryptedData.encryptedData) {
        throw new ValidationError(
          'Invalid encrypted data object',
          'encryptedData',
          typeof encryptedData
        );
      }
      
      const params = new URLSearchParams();
      params.set('picc_data', encryptedData.encryptedData.picc);
      params.set('cmac', encryptedData.encryptedData.cmac);
      
      if (encryptedData.encryptedData.enc) {
        params.set('enc', encryptedData.encryptedData.enc);
      }
      
      return `${baseURL}?${params.toString()}`;
    } catch (error) {
      throw new EncryptionError(
        `URL generation failed: ${error.message}`,
        'generateURL',
        { baseURL, hasEncryptedData: !!encryptedData }
      );
    }
  }
  
  /**
   * Generate query string format from encrypted data
   * 
   * @param {Object} encryptedData - Result from encrypt() method
   * @returns {string} Query string with encrypted parameters
   */
  static generateQueryString(encryptedData) {
    try {
      if (!encryptedData || !encryptedData.encryptedData) {
        throw new ValidationError(
          'Invalid encrypted data object',
          'encryptedData',
          typeof encryptedData
        );
      }
      
      const params = new URLSearchParams();
      params.set('picc_data', encryptedData.encryptedData.picc);
      params.set('cmac', encryptedData.encryptedData.cmac);
      
      if (encryptedData.encryptedData.enc) {
        params.set('enc', encryptedData.encryptedData.enc);
      }
      
      return params.toString();
    } catch (error) {
      throw new EncryptionError(
        `Query string generation failed: ${error.message}`,
        'generateQueryString'
      );
    }
  }
  
  /**
   * Generate secure master key
   * 
   * @param {Object} options - Generation options
   * @returns {string} 32-character hexadecimal master key
   */
  static generateMasterKey(options = {}) {
    try {
      const crypto = require('crypto');
      const keyBytes = crypto.randomBytes(16);
      const hexKey = keyBytes.toString('hex').toUpperCase();
      
      if (hexKey.length !== 32 || !/^[0-9A-F]+$/.test(hexKey)) {
        throw new EncryptionError(
          'Generated key validation failed',
          'generateMasterKey'
        );
      }
      
      return hexKey;
    } catch (error) {
      throw new EncryptionError(
        `Master key generation failed: ${error.message}`,
        'generateMasterKey'
      );
    }
  }
  
  /**
   * Validate and convert UID to Buffer
   * 
   * @param {string|Buffer} uid - UID to validate
   * @returns {Buffer} Validated UID buffer
   */
  static _validateAndConvertUID(uid) {
    if (Buffer.isBuffer(uid)) {
      if (uid.length !== 7) {
        throw new ValidationError(
          'UID buffer must be exactly 7 bytes',
          'uid',
          `${uid.length} bytes`,
          '7 bytes'
        );
      }
      return uid;
    }
    
    if (typeof uid === 'string') {
      if (uid.length !== 14) {
        throw new ValidationError(
          'UID hex string must be exactly 14 characters (7 bytes)',
          'uid',
          `${uid.length} characters`,
          '14 characters'
        );
      }
      
      if (!/^[0-9A-Fa-f]+$/.test(uid)) {
        throw new ValidationError(
          'UID contains invalid hex characters',
          'uid',
          uid
        );
      }
      
      return Buffer.from(uid, 'hex');
    }
    
    throw new ValidationError(
      'UID must be a 7-byte Buffer or 14-character hex string',
      'uid',
      typeof uid
    );
  }
  
  /**
   * Validate and convert counter to Buffer
   * 
   * @param {number|Buffer} scanCount - Counter to validate
   * @returns {Buffer} Validated counter buffer
   */
  static _validateAndConvertCounter(scanCount) {
    if (Buffer.isBuffer(scanCount)) {
      if (scanCount.length !== 3) {
        throw new ValidationError(
          'Counter buffer must be exactly 3 bytes',
          'scanCount',
          `${scanCount.length} bytes`,
          '3 bytes'
        );
      }
      return scanCount;
    }
    
    if (typeof scanCount === 'number') {
      if (!Number.isInteger(scanCount) || scanCount < 0 || scanCount > 0xFFFFFF) {
        throw new ValidationError(
          'Counter must be an integer between 0 and 16777215 (2^24 - 1)',
          'scanCount',
          scanCount,
          '0 to 16777215'
        );
      }
      return this._numberToCounter(scanCount);
    }
    
    throw new ValidationError(
      'Counter must be a number or 3-byte Buffer',
      'scanCount',
      typeof scanCount
    );
  }
  
  /**
   * Prepare file data for encryption
   * 
   * @param {string|Buffer} fileData - File data to prepare
   * @returns {Buffer} Prepared file data buffer
   */
  static _prepareFileData(fileData) {
    if (Buffer.isBuffer(fileData)) {
      const paddedLength = Math.ceil(fileData.length / 16) * 16;
      if (fileData.length === paddedLength) {
        return fileData;
      }
      const paddedBuffer = Buffer.alloc(paddedLength, 0x00);
      fileData.copy(paddedBuffer, 0);
      return paddedBuffer;
    } else if (typeof fileData === 'string') {
      const dataBytes = Buffer.from(fileData, 'utf8');
      const paddedLength = Math.ceil(dataBytes.length / 16) * 16;
      const fileBuffer = Buffer.alloc(paddedLength, 0x00);
      dataBytes.copy(fileBuffer, 0);
      return fileBuffer;
    } else {
      throw new ValidationError(
        'File data must be a string or Buffer',
        'fileData',
        typeof fileData
      );
    }
  }
  
  /**
   * Build PICC data according to SDM profile
   * 
   * @param {Buffer} uid - UID buffer
   * @param {Buffer} counter - Counter buffer
   * @param {Object} profile - SDM profile
   * @returns {Buffer} PICC data buffer
   */
  static _buildPiccData(uid, counter, profile) {
    try {
      const piccData = Buffer.alloc(profile.piccDataLength || 16, 0x00);
      
      piccData[0] = 0xC7;
      
      if (profile.includeUID && uid) {
        const uidStart = profile.uidOffset || 1;
        const uidLen = Math.min(uid.length, profile.uidLength || 7);
        
        if (uidStart + uidLen > piccData.length) {
          throw new EncryptionError(
            'UID data extends beyond PICC data length',
            'buildPiccData',
            { uidStart, uidLen, piccLength: piccData.length }
          );
        }
        
        for (let i = 0; i < uidLen; i++) {
          piccData[uidStart + i] = uid[i];
        }
      }
      
      if (profile.includeCounter && counter) {
        const counterStart = profile.counterOffset || 8;
        const counterLen = Math.min(counter.length, profile.counterLength || 3);
        
        if (counterStart + counterLen > piccData.length) {
          throw new EncryptionError(
            'Counter data extends beyond PICC data length',
            'buildPiccData',
            { counterStart, counterLen, piccLength: piccData.length }
          );
        }
        
        for (let i = 0; i < counterLen; i++) {
          piccData[counterStart + i] = counter[i];
        }
      }
      
      return piccData;
    } catch (error) {
      throw new EncryptionError(
        `PICC data building failed: ${error.message}`,
        'buildPiccData'
      );
    }
  }
  
  /**
   * Derive session keys using specified method
   * 
   * @param {Buffer} masterKey - Master key buffer
   * @param {Buffer} uid - UID buffer
   * @param {Buffer} counter - Counter buffer
   * @param {string} method - Key derivation method
   * @returns {Object} Session keys
   */
  static _deriveKeys(masterKey, uid, counter, method) {
    const derivationMethods = {
      'ntag424Official': KeyDerivation.ntag424Official,
      'hkdf': KeyDerivation.hkdf,
      'pbkdf2': KeyDerivation.pbkdf2,
      'simpleHash': KeyDerivation.simpleHash
    };
    
    const derivationFunction = derivationMethods[method];
    if (!derivationFunction) {
      throw new EncryptionError(
        `Unknown key derivation method: ${method}`,
        'deriveKeys'
      );
    }
    
    const result = derivationFunction(masterKey, uid, counter);
    
    return {
      encKey: Buffer.isBuffer(result.encKey) ? result.encKey : Buffer.from(result.encKey),
      macKey: Buffer.isBuffer(result.macKey) ? result.macKey : Buffer.from(result.macKey),
      method: result.method || method
    };
  }
  
  /**
   * Convert number to 3-byte counter buffer
   * 
   * @param {number} number - Number to convert
   * @returns {Buffer} 3-byte counter buffer
   */
  static _numberToCounter(number) {
    const buffer = Buffer.alloc(3);
    buffer.writeUIntBE(number, 0, 3);
    return buffer;
  }
  
  /**
   * Convert counter buffer to number
   * 
   * @param {Buffer} buffer - Counter buffer
   * @returns {number} Counter value
   */
  static _counterToNumber(buffer) {
    return buffer.readUIntBE(0, Math.min(buffer.length, 3));
  }
}

module.exports = Encoder;
