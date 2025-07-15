const AES = require('./aes');
const CMAC = require('./cmac');
const SDMConfig = require('./sdm-config');
const KeyDerivation = require('./key-derivation');

/**
 * NTAG424 Encryption Helper Methods
 * 
 * Simple helper methods for encrypting data using NTAG424 algorithms.
 * Returns encrypted data components in various formats.
 */
class Encoder {
  
  /**
   * Encrypt NTAG424 data using zero vector approach
   * 
   * @param {string} masterKey - Master key as hex string (32 characters)
   * @param {string|Buffer} uid - Tag UID (7 bytes as hex string or Buffer)
   * @param {number|Buffer} scanCount - Scan counter (number or 3-byte Buffer)
   * @param {string|Buffer} fileData - Optional file data to encrypt
   * @param {Object} options - Optional configuration
   * @returns {Object} Object containing original data and encrypted components
   */
  static encrypt(masterKey, uid, scanCount, fileData = null, options = {}) {
    try {
      const {
        keyDerivationMethod = 'ntag424Official',
        sdmProfile = fileData ? 'full' : 'uidCounter'
      } = options;
      
      if (!masterKey || typeof masterKey !== 'string' || masterKey.length !== 32) {
        throw new Error('Master key must be a 32-character hex string');
      }
      
      const uidBuffer = this._validateAndConvertUID(uid);
      const counterBuffer = this._validateAndConvertCounter(scanCount);
      const masterKeyBuffer = Buffer.from(masterKey, 'hex');
      
      const sdmConfig = typeof sdmProfile === 'string' 
        ? SDMConfig.getProfile(sdmProfile)
        : sdmProfile;
      
      if (!sdmConfig) {
        throw new Error('Invalid SDM profile');
      }
      
      const zeroUID = Buffer.alloc(7, 0);
      const zeroCounter = Buffer.alloc(3, 0);
      
      const piccData = this._buildPiccData(uidBuffer, counterBuffer, sdmConfig);
      
      const sessionKeys = this._deriveKeys(masterKeyBuffer, zeroUID, zeroCounter, keyDerivationMethod);
      
      const encryptedPicc = AES.cbcEncrypt(sessionKeys.encKey, piccData);
      
      let encryptedFile = null;
      let cmacData = encryptedPicc;
      
      if (fileData) {
        const fileBuffer = this._prepareFileData(fileData);
        encryptedFile = AES.cbcEncrypt(sessionKeys.encKey, fileBuffer);
        cmacData = Buffer.concat([encryptedPicc, encryptedFile]);
      }
      
      const cmac = CMAC.calculate(sessionKeys.macKey, cmacData).slice(0, 8);
      
      const result = {
        originalData: {
          uid: uidBuffer.toString('hex').toUpperCase(),
          scanCount: this._counterToNumber(counterBuffer),
          masterKey,
          keyDerivationMethod
        },
        encryptedData: {
          picc: encryptedPicc.toString('hex').toUpperCase(),
          cmac: cmac.toString('hex').toUpperCase()
        }
      };
      
      if (fileData) {
        result.originalData.fileData = fileData.toString();
        result.encryptedData.enc = encryptedFile.toString('hex').toUpperCase();
      }
      
      return result;
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
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
        throw new Error('Invalid encrypted data object');
      }
      
      const params = new URLSearchParams();
      params.set('picc_data', encryptedData.encryptedData.picc);
      params.set('cmac', encryptedData.encryptedData.cmac);
      
      if (encryptedData.encryptedData.enc) {
        params.set('enc', encryptedData.encryptedData.enc);
      }
      
      return `${baseURL}?${params.toString()}`;
    } catch (error) {
      throw new Error(`URL generation failed: ${error.message}`);
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
        throw new Error('Invalid encrypted data object');
      }
      
      const params = new URLSearchParams();
      params.set('picc_data', encryptedData.encryptedData.picc);
      params.set('cmac', encryptedData.encryptedData.cmac);
      
      if (encryptedData.encryptedData.enc) {
        params.set('enc', encryptedData.encryptedData.enc);
      }
      
      return params.toString();
    } catch (error) {
      throw new Error(`Query string generation failed: ${error.message}`);
    }
  }
  
  /**
   * Generate secure master key
   * 
   * @param {Object} options - Generation options
   * @param {boolean} options.includeSpecialChars - Include special characters (default: false for hex compatibility)
   * @returns {string} 32-character hexadecimal master key
   */
  static generateMasterKey(options = {}) {
    try {
      const { includeSpecialChars = false } = options;
      
      const keyBytes = Buffer.alloc(16);
      
      for (let i = 0; i < 16; i++) {
        keyBytes[i] = Math.floor(Math.random() * 256);
      }
      
      const hexKey = keyBytes.toString('hex').toUpperCase();
      
      if (hexKey.length !== 32 || !/^[0-9A-F]+$/.test(hexKey)) {
        throw new Error('Generated key validation failed');
      }
      
      return hexKey;
    } catch (error) {
      throw new Error(`Master key generation failed: ${error.message}`);
    }
  }
  
  static _validateAndConvertUID(uid) {
    if (Buffer.isBuffer(uid)) {
      if (uid.length !== 7) {
        throw new Error('UID buffer must be exactly 7 bytes');
      }
      return uid;
    }
    
    if (typeof uid === 'string') {
      if (uid.length !== 14) {
        throw new Error('UID hex string must be exactly 14 characters (7 bytes)');
      }
      
      if (!/^[0-9A-Fa-f]+$/.test(uid)) {
        throw new Error('UID contains invalid hex characters');
      }
      
      return Buffer.from(uid, 'hex');
    }
    
    throw new Error('UID must be a 7-byte Buffer or 14-character hex string');
  }
  
  static _validateAndConvertCounter(scanCount) {
    if (Buffer.isBuffer(scanCount)) {
      if (scanCount.length !== 3) {
        throw new Error('Counter buffer must be exactly 3 bytes');
      }
      return scanCount;
    }
    
    if (typeof scanCount === 'number') {
      if (!Number.isInteger(scanCount) || scanCount < 0 || scanCount > 0xFFFFFF) {
        throw new Error('Counter must be an integer between 0 and 16777215 (2^24 - 1)');
      }
      return this._numberToCounter(scanCount);
    }
    
    throw new Error('Counter must be a number or 3-byte Buffer');
  }
  
  static _prepareFileData(fileData) {
    const fileBuffer = Buffer.alloc(16, 0x00);
    
    if (Buffer.isBuffer(fileData)) {
      fileData.copy(fileBuffer, 0, 0, Math.min(fileData.length, 16));
    } else if (typeof fileData === 'string') {
      const dataBytes = Buffer.from(fileData, 'utf8');
      dataBytes.copy(fileBuffer, 0, 0, Math.min(dataBytes.length, 16));
    } else {
      throw new Error('File data must be a string or Buffer');
    }
    
    return fileBuffer;
  }
  
  static _buildPiccData(uid, counter, sdmConfig) {
    try {
      const piccData = Buffer.alloc(sdmConfig.piccDataLength || 16, 0x00);
      
      piccData[0] = 0xC7;
      
      if (sdmConfig.includeUID && uid) {
        const uidStart = sdmConfig.uidOffset || 1;
        const uidLen = Math.min(uid.length, sdmConfig.uidLength || 7);
        
        if (uidStart + uidLen > piccData.length) {
          throw new Error('UID data extends beyond PICC data length');
        }
        
        for (let i = 0; i < uidLen; i++) {
          piccData[uidStart + i] = uid[i];
        }
      }
      
      if (sdmConfig.includeCounter && counter) {
        const counterStart = sdmConfig.counterOffset || 8;
        const counterLen = Math.min(counter.length, sdmConfig.counterLength || 3);
        
        if (counterStart + counterLen > piccData.length) {
          throw new Error('Counter data extends beyond PICC data length');
        }
        
        for (let i = 0; i < counterLen; i++) {
          piccData[counterStart + i] = counter[i];
        }
      }
      
      return piccData;
    } catch (error) {
      throw new Error(`PICC data building failed: ${error.message}`);
    }
  }
  
  static _deriveKeys(masterKey, uid, counter, method) {
    const derivationMethods = {
      'ntag424Official': KeyDerivation.ntag424Official,
      'hkdf': KeyDerivation.hkdf,
      'pbkdf2': KeyDerivation.pbkdf2,
      'simpleHash': KeyDerivation.simpleHash
    };
    
    const derivationFunction = derivationMethods[method];
    if (!derivationFunction) {
      throw new Error(`Unknown key derivation method: ${method}`);
    }
    
    const result = derivationFunction(masterKey, uid, counter);
    
    return {
      encKey: Buffer.isBuffer(result.encKey) ? result.encKey : Buffer.from(result.encKey),
      macKey: Buffer.isBuffer(result.macKey) ? result.macKey : Buffer.from(result.macKey),
      method: result.method
    };
  }
  
  static _numberToCounter(number) {
    const buffer = Buffer.alloc(3);
    buffer.writeUIntBE(number, 0, 3);
    return buffer;
  }
  
  static _counterToNumber(buffer) {
    return buffer.readUIntBE(0, Math.min(buffer.length, 3));
  }
}

module.exports = Encoder;
