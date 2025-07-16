const crypto = require('crypto');
const { ValidationError, SecurityError } = require('./error-types');
const { MemoryManager } = require('./secure-memory');

let aesCmac;
try {
  const { aesCmac: importedAesCmac } = require('node-aes-cmac');
  aesCmac = importedAesCmac;
} catch (error) {
  aesCmac = (key, data) => {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest().slice(0, 16);
  };
  console.warn('Warning: Using fallback CMAC implementation. Install node-aes-cmac for production use.');
}

/**
 * Key Derivation Methods
 * 
 * This class provides various cryptographic key derivation functions for generating
 * session keys from master keys. Different methods offer different security levels
 * and performance characteristics.
 */
class KeyDerivation {
  
  /**
   * NTAG424 Official CMAC-based Key Derivation
   * 
   * @param {Buffer} masterKey - The master key (16 bytes) for key derivation
   * @param {Buffer} uid - The tag UID (typically 7 bytes)
   * @param {Buffer} readCounter - The read counter (3 bytes)
   * @param {Object} options - Optional configuration parameters
   * @returns {Object} Object containing encKey, macKey, and method name
   */
  static ntag424Official(masterKey, uid, readCounter, options = {}) {
    try {
      if (!Buffer.isBuffer(masterKey) || masterKey.length !== 16) {
        throw new ValidationError('Master key must be a 16-byte Buffer', 'masterKey', masterKey?.length, 16);
      }
      
      if (!Buffer.isBuffer(uid)) {
        throw new ValidationError('UID must be a Buffer', 'uid', typeof uid, 'Buffer');
      }
      
      if (!Buffer.isBuffer(readCounter)) {
        throw new ValidationError('Read counter must be a Buffer', 'readCounter', typeof readCounter, 'Buffer');
      }
      
      const { useCMAC = true, keyLength = 16 } = options;
      
      const sv1 = KeyDerivation.buildSV1(uid, readCounter, options);
      const sv2 = KeyDerivation.buildSV2(uid, readCounter, options);
      
      let encKey, macKey;
      
      if (useCMAC) {
        const cmac1 = aesCmac(masterKey, sv1);
        const cmac2 = aesCmac(masterKey, sv2);
        encKey = Buffer.from(cmac1).slice(0, keyLength);
        macKey = Buffer.from(cmac2).slice(0, keyLength);
      } else {
        const { AES } = require('./aes');
        encKey = AES.ecbEncrypt(masterKey, sv1.slice(0, 16)).slice(0, keyLength);
        macKey = AES.ecbEncrypt(masterKey, sv2.slice(0, 16)).slice(0, keyLength);
      }
      
      return { 
        encKey: Buffer.from(encKey), 
        macKey: Buffer.from(macKey), 
        method: 'ntag424-official' 
      };
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`NTAG424 key derivation failed: ${error.message}`, 'KEY_DERIVATION_FAILURE');
    }
  }
  
  /**
   * HKDF-based Key Derivation
   * 
   * @param {Buffer} masterKey - The master key for derivation
   * @param {Buffer} uid - The tag UID
   * @param {Buffer} readCounter - The read counter
   * @param {Object} options - Configuration options
   * @returns {Object} Object containing encKey, macKey, and method name
   */
  static hkdf(masterKey, uid, readCounter, options = {}) {
    try {
      if (!Buffer.isBuffer(masterKey)) {
        throw new ValidationError('Master key must be a Buffer', 'masterKey', typeof masterKey, 'Buffer');
      }
      
      const { 
        algorithm = 'sha256',
        salt = null,
        info = 'NTAG424-SESSION-KEYS',
        keyLength = 32 
      } = options;
      
      const inputSalt = salt || Buffer.concat([uid || Buffer.alloc(0), readCounter || Buffer.alloc(0)]);
      const infoBuffer = Buffer.from(info, 'utf8');
      
      const derivedKeys = crypto.hkdfSync(algorithm, masterKey, inputSalt, infoBuffer, keyLength);
      const derivedKeysBuffer = Buffer.from(derivedKeys);
      
      return {
        encKey: derivedKeysBuffer.slice(0, keyLength / 2),
        macKey: derivedKeysBuffer.slice(keyLength / 2),
        method: 'hkdf'
      };
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`HKDF key derivation failed: ${error.message}`, 'KEY_DERIVATION_FAILURE');
    }
  }
  
  /**
   * PBKDF2-based Key Derivation
   * 
   * @param {Buffer} masterKey - The master key for derivation
   * @param {Buffer} uid - The tag UID
   * @param {Buffer} readCounter - The read counter
   * @param {Object} options - Configuration options
   * @returns {Object} Object containing encKey, macKey, and method name
   */
  static pbkdf2(masterKey, uid, readCounter, options = {}) {
    try {
      if (!Buffer.isBuffer(masterKey)) {
        throw new ValidationError('Master key must be a Buffer', 'masterKey', typeof masterKey, 'Buffer');
      }
      
      const { 
        iterations = 10000,
        algorithm = 'sha256',
        saltPrefix = 'NTAG424',
        keyLength = 32 
      } = options;
      
      if (iterations < 1000) {
        throw new ValidationError('Iterations must be at least 1000 for security', 'iterations', iterations, '>=1000');
      }
      
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
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`PBKDF2 key derivation failed: ${error.message}`, 'KEY_DERIVATION_FAILURE');
    }
  }
  
  /**
   * Simple Hash-based Key Derivation
   * 
   * @param {Buffer} masterKey - The master key for derivation
   * @param {Buffer} uid - The tag UID
   * @param {Buffer} readCounter - The read counter
   * @param {Object} options - Configuration options
   * @returns {Object} Object containing encKey, macKey, and method name
   */
  static simpleHash(masterKey, uid, readCounter, options = {}) {
    try {
      if (!Buffer.isBuffer(masterKey)) {
        throw new ValidationError('Master key must be a Buffer', 'masterKey', typeof masterKey, 'Buffer');
      }
      
      const { algorithm = 'sha256', keyLength = 16 } = options;
      
      const validAlgorithms = ['sha256', 'sha512', 'sha1'];
      if (!validAlgorithms.includes(algorithm)) {
        throw new ValidationError(`Algorithm must be one of: ${validAlgorithms.join(', ')}`, 'algorithm', algorithm);
      }
      
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
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`Simple hash key derivation failed: ${error.message}`, 'KEY_DERIVATION_FAILURE');
    }
  }
  
  /**
   * Custom Key Derivation
   * 
   * @param {Buffer} masterKey - The master key for derivation
   * @param {Buffer} uid - The tag UID
   * @param {Buffer} readCounter - The read counter
   * @param {Function} derivationFunction - User-provided derivation function
   * @returns {Object} Object containing encKey, macKey, and method name
   */
  static custom(masterKey, uid, readCounter, derivationFunction) {
    try {
      if (!Buffer.isBuffer(masterKey)) {
        throw new ValidationError('Master key must be a Buffer', 'masterKey', typeof masterKey, 'Buffer');
      }
      
      if (typeof derivationFunction !== 'function') {
        throw new ValidationError('Derivation function must be a function', 'derivationFunction', typeof derivationFunction, 'function');
      }
      
      const result = derivationFunction(masterKey, uid, readCounter);
      
      if (!result || !result.encKey || !result.macKey) {
        throw new ValidationError('Custom derivation function must return object with encKey and macKey', 'derivationFunction', typeof result);
      }
      
      return { 
        encKey: Buffer.from(result.encKey),
        macKey: Buffer.from(result.macKey),
        method: 'custom' 
      };
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`Custom key derivation failed: ${error.message}`, 'KEY_DERIVATION_FAILURE');
    }
  }
  
  /**
   * Build SV1 (Session Vector 1) for NTAG424 encryption key derivation
   * 
   * @param {Buffer} uid - The tag UID
   * @param {Buffer} readCounter - The read counter
   * @param {Object} options - Configuration options
   * @returns {Buffer} The constructed SV1 buffer
   */
  static buildSV1(uid, readCounter, options = {}) {
    try {
      const { svLength = 32, encLabel = '3CC300010080' } = options;
      
      if (svLength < 16) {
        throw new ValidationError('SV length must be at least 16 bytes', 'svLength', svLength, '>=16');
      }
      
      const sv1 = Buffer.alloc(svLength, 0x00);
      
      let offset = 0;
      
      const labelBuffer = Buffer.from(encLabel, 'hex');
      labelBuffer.copy(sv1, offset);
      offset += labelBuffer.length;
      
      if (uid && uid.length > 0) {
        const copyLength = Math.min(uid.length, svLength - offset);
        uid.copy(sv1, offset, 0, copyLength);
        offset += copyLength;
      }
      
      if (readCounter && readCounter.length > 0) {
        const copyLength = Math.min(readCounter.length, svLength - offset);
        readCounter.copy(sv1, offset, 0, copyLength);
      }
      
      return sv1;
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`SV1 construction failed: ${error.message}`, 'SV_CONSTRUCTION_FAILURE');
    }
  }
  
  /**
   * Build SV2 (Session Vector 2) for NTAG424 MAC key derivation
   * 
   * @param {Buffer} uid - The tag UID
   * @param {Buffer} readCounter - The read counter
   * @param {Object} options - Configuration options
   * @returns {Buffer} The constructed SV2 buffer
   */
  static buildSV2(uid, readCounter, options = {}) {
    try {
      const { svLength = 32, macLabel = '3CC300010081' } = options;
      
      if (svLength < 16) {
        throw new ValidationError('SV length must be at least 16 bytes', 'svLength', svLength, '>=16');
      }
      
      const sv2 = Buffer.alloc(svLength, 0x00);
      
      let offset = 0;
      
      const labelBuffer = Buffer.from(macLabel, 'hex');
      labelBuffer.copy(sv2, offset);
      offset += labelBuffer.length;
      
      if (uid && uid.length > 0) {
        const copyLength = Math.min(uid.length, svLength - offset);
        uid.copy(sv2, offset, 0, copyLength);
        offset += copyLength;
      }
      
      if (readCounter && readCounter.length > 0) {
        const copyLength = Math.min(readCounter.length, svLength - offset);
        readCounter.copy(sv2, offset, 0, copyLength);
      }
      
      return sv2;
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new SecurityError(`SV2 construction failed: ${error.message}`, 'SV_CONSTRUCTION_FAILURE');
    }
  }
}

module.exports = KeyDerivation;
