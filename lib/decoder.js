const AES = require('./aes');
const CMAC = require('./cmac');
const SDMConfig = require('./sdm-config');
const DataParser = require('./data-parser');
const KeyDerivation = require('./key-derivation');

/**
 * Main NTAG424 Decoder Class
 * 
 * Decrypts NTAG424 SDM data when you know the master key and expected structure.
 * For real-world use where you know what UID/counter to expect.
 */
class Decoder {
  
  /**
   * Create a new NTAG424 Decoder instance
   * 
   * @param {string} masterKey - Master key as hexadecimal string (32 characters for 16 bytes)
   * @param {Object} options - Configuration options for the decoder
   */
  constructor(masterKey, options = {}) {
    try {
      if (!masterKey || typeof masterKey !== 'string' || masterKey.length !== 32) {
        throw new Error('Master key must be a 32-character hex string');
      }
      
      if (!/^[0-9A-Fa-f]+$/.test(masterKey)) {
        throw new Error('Master key contains invalid hex characters');
      }
      
      this.masterKey = Buffer.from(masterKey, 'hex');
      this.options = {
        keyDerivationMethod: 'ntag424Official',
        sdmProfile: 'uidCounter',
        validateCMAC: true,
        strictValidation: false,
        ...options
      };
      
      this._validateOptions();
    } catch (error) {
      throw new Error(`Decoder initialization failed: ${error.message}`);
    }
  }
  
  /**
   * Decrypt NTAG424 SDM data
   * 
   * @param {string|Object} input - NTAG424 data as URL, query string, or object
   * @param {Object} customOptions - Optional override options for this specific operation
   * @returns {Object} Decryption result object
   */
  decrypt(input, customOptions = {}) {
    const options = { ...this.options, ...customOptions };
    
    try {
      const data = this._parseInput(input);
      
      if (options.strictValidation) {
        this._validateInput(data);
      }
      
      const piccData = DataParser.hexToBuffer(data.picc, 'PICC data');
      const encData = data.enc ? DataParser.hexToBuffer(data.enc, 'ENC data') : null;
      const cmacData = DataParser.hexToBuffer(data.cmac, 'CMAC data');
      
      const sdmConfig = typeof options.sdmProfile === 'string'
        ? SDMConfig.getProfile(options.sdmProfile)
        : options.sdmProfile;
      
      const result = this._performDecryption(piccData, encData, cmacData, sdmConfig, options);
      
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
        error: error.message
      };
    }
  }
  
  /**
   * Perform the actual decryption process using zero vector approach
   * 
   * Simple and clean: always use zero UID/counter for key derivation,
   * then extract actual UID/counter from the decrypted data.
   */
  _performDecryption(piccData, encData, cmacData, sdmConfig, options) {
    try {
      const zeroUID = Buffer.alloc(7, 0);
      const zeroCounter = Buffer.alloc(3, 0);
      
      const sessionKeys = this._deriveKeys(zeroUID, zeroCounter, options.keyDerivationMethod);
      
      const decryptedPicc = AES.cbcDecrypt(sessionKeys.encKey, piccData);
      
      const piccInfo = DataParser.extractPiccData(decryptedPicc, sdmConfig);
      
      if (!this._isValidDecryption(decryptedPicc, piccInfo)) {
        throw new Error('Invalid decrypted data structure');
      }
      
      let decryptedEnc = null;
      if (encData) {
        try {
          decryptedEnc = AES.cbcDecrypt(sessionKeys.encKey, encData);
        } catch (encDecryptError) {
          throw new Error(`File data decryption failed: ${encDecryptError.message}`);
        }
      }
      
      let cmacValid = true;
      if (options.validateCMAC) {
        try {
          const dataToVerify = Buffer.concat([
            piccData,
            encData || Buffer.alloc(0)
          ]);
          cmacValid = CMAC.verify(sessionKeys.macKey, dataToVerify, cmacData);
        } catch (cmacError) {
          cmacValid = false;
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
        piccInfo
      };
      
    } catch (error) {
      throw new Error(`Zero vector decryption failed: ${error.message}`);
    }
  }
  
  /**
   * Validate if decrypted data has proper NTAG424 structure
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
  
  _extractFileData(decryptedEnc) {
    if (!decryptedEnc || !Buffer.isBuffer(decryptedEnc)) {
      return null;
    }
    
    try {
      const utf8String = decryptedEnc.toString('utf8').replace(/\0+$/, '');
      return utf8String.length > 0 ? utf8String : null;
    } catch (error) {
      try {
        return this._cleanHexString(decryptedEnc.toString('hex'));
      } catch (hexError) {
        return null;
      }
    }
  }
  
  _cleanHexString(hexString) {
    return hexString.replace(/(00)+$/, '');
  }
  
  _validateOptions() {
    const validMethods = ['ntag424Official', 'hkdf', 'pbkdf2', 'simpleHash'];
    if (!validMethods.includes(this.options.keyDerivationMethod)) {
      throw new Error(`Invalid key derivation method: ${this.options.keyDerivationMethod}`);
    }
    
    if (typeof this.options.sdmProfile === 'string') {
      const validProfiles = SDMConfig.getAvailableProfiles();
      if (!validProfiles.includes(this.options.sdmProfile)) {
        throw new Error(`Invalid SDM profile: ${this.options.sdmProfile}`);
      }
    } else if (typeof this.options.sdmProfile === 'object') {
      const validation = SDMConfig.validateProfile(this.options.sdmProfile);
      if (!validation.isValid) {
        throw new Error(`Invalid SDM profile: ${validation.errors.join(', ')}`);
      }
    }
  }
  
  _parseInput(input) {
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
        throw new Error('Invalid input format');
      }
    } catch (error) {
      throw new Error(`Input parsing failed: ${error.message}`);
    }
  }
  
  _validateInput(data) {
    const validation = DataParser.validateParsedData(data, {
      requirePicc: true,
      requireCmac: true,
      strictHex: true
    });
    
    if (!validation.isValid) {
      throw new Error(validation.errors.join(', '));
    }
  }
  
  _deriveKeys(uid, readCounter, method) {
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
    
    const result = derivationFunction(this.masterKey, uid, readCounter);
    
    return {
      encKey: Buffer.isBuffer(result.encKey) ? result.encKey : Buffer.from(result.encKey),
      macKey: Buffer.isBuffer(result.macKey) ? result.macKey : Buffer.from(result.macKey),
      method: result.method || method
    };
  }
}

module.exports = Decoder;
