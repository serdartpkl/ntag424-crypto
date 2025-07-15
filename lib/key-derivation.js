const crypto = require('crypto');

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
   * const keys = KeyDerivation.ntag424Official(masterKey, uid, counter);
   */
  static ntag424Official(masterKey, uid, readCounter, options = {}) {
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
   * const keys = KeyDerivation.hkdf(masterKey, uid, counter, {
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
    const derivedKeysBuffer = Buffer.from(derivedKeys);
    
    return {
      encKey: derivedKeysBuffer.slice(0, keyLength / 2),
      macKey: derivedKeysBuffer.slice(keyLength / 2),
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
   * const keys = KeyDerivation.pbkdf2(masterKey, uid, counter, {
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
   * const keys = KeyDerivation.simpleHash(masterKey, uid, counter, {
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
   * const keys = KeyDerivation.custom(masterKey, uid, counter, customDerivation);
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

module.exports = KeyDerivation;
