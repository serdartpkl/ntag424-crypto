# NTAG424 Crypto Library

A comprehensive, hardware-agnostic cryptographic library for NTAG424 DNA encryption/decryption operations. Provides complete server-side processing capabilities without requiring NFC hardware dependencies.

## Real-Life Usage Examples

### 🔧 Basic Decryption
```javascript
const NTAG424Crypto = require('./ntag424-crypto');

// Simple decryption with default settings
const decoder = new NTAG424Crypto.Decoder('00112233445566778899AABBCCDDEEFF');
const result = decoder.decrypt('https://example.com/nfc?picc_data=ABC123&cmac=789ABC');

if (result.success && result.cmacValid) {
    console.log(`UID: ${result.uid}`);
    console.log(`Counter: ${result.readCounter}`);
}
```

### 🔧 Custom Configuration
```javascript
// High-security configuration
const secureDecoder = new NTAG424Crypto.Decoder('AABBCCDDEEFF00112233445566778899', {
    keyDerivationMethod: 'hkdf',
    sdmProfile: 'full',
    validateCMAC: true,
    strictValidation: true
});

const result = secureDecoder.decrypt(ntagUrl);
```

### 🔧 Performance-Optimized Configuration
```javascript
// Fast configuration for high-throughput applications
const fastDecoder = new NTAG424Crypto.Decoder(masterKey, {
    keyDerivationMethod: 'simpleHash',
    sdmProfile: 'uidCounter',
    validateCMAC: false // Skip CMAC for speed
});
```

### 🔧 Different Input Formats
```javascript
const decoder = new NTAG424Crypto.Decoder(masterKey);

// From complete URL
const result1 = decoder.decrypt('https://example.com/nfc?picc_data=ABC123&enc=DEF456&cmac=789ABC');

// From query string only
const result2 = decoder.decrypt('picc_data=ABC123&cmac=DEF456');

// From object
const result3 = decoder.decrypt({
    picc: 'ABC123',
    enc: 'DEF456',
    cmac: '789ABC'
});
```

### 🔧 Error Handling
```javascript
const decoder = new NTAG424Crypto.Decoder(masterKey);
const result = decoder.decrypt(ntagData);

if (!result.success) {
    console.error(`Decryption failed: ${result.error}`);
    return;
}

if (!result.cmacValid) {
    console.error('CMAC validation failed - data may be tampered');
    return;
}

// Process authenticated data
console.log('Data is authentic and valid');
```

### 🔧 Custom Key Derivation
```javascript
// Using different key derivation methods
const keys1 = NTAG424Crypto.KeyDerivation.ntag424Official(masterKey, uid, counter);
const keys2 = NTAG424Crypto.KeyDerivation.hkdf(masterKey, uid, counter);
const keys3 = NTAG424Crypto.KeyDerivation.pbkdf2(masterKey, uid, counter, { iterations: 5000 });

console.log(`Encryption Key: ${keys1.encKey.toString('hex')}`);
console.log(`MAC Key: ${keys1.macKey.toString('hex')}`);
```

### 🔧 Custom SDM Profile
```javascript
// Create custom SDM configuration
const customProfile = NTAG424Crypto.SDMConfig.createCustomProfile({
    includeUID: true,
    includeCounter: false,
    uidOffset: 2,
    uidLength: 6
});

const decoder = new NTAG424Crypto.Decoder(masterKey, {
    sdmProfile: customProfile
});
```

### 🔧 Direct AES Operations
```javascript
// Manual AES encryption/decryption
const key = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
const data = Buffer.from('Hello World');

const encrypted = NTAG424Crypto.AES.cbcEncrypt(key, data);
const decrypted = NTAG424Crypto.AES.cbcDecrypt(key, encrypted);

console.log(`Original: ${data.toString()}`);
console.log(`Decrypted: ${decrypted.toString()}`);
```

### 🔧 CMAC Verification
```javascript
// Manual CMAC calculation and verification
const key = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
const data = Buffer.from('Data to authenticate');

const cmac = NTAG424Crypto.CMAC.calculate(key, data);
const isValid = NTAG424Crypto.CMAC.verify(key, data, cmac);

console.log(`CMAC: ${cmac.toString('hex')}`);
console.log(`Valid: ${isValid}`);
```

### 🔧 Data Parsing Utilities
```javascript
// Parse NTAG424 URL manually
const parsed = NTAG424Crypto.DataParser.parseURL('https://example.com/nfc?picc_data=ABC&cmac=DEF');
console.log(parsed); // { picc: 'ABC', enc: null, cmac: 'DEF', ... }

// Validate hex strings
const isValid = NTAG424Crypto.DataParser.validateHexString('ABC123', 6);
console.log(`Valid hex: ${isValid}`); // true

// Extract data from decrypted PICC
const piccInfo = NTAG424Crypto.DataParser.extractPiccData(decryptedBuffer, 'uidCounter');
console.log(`UID: ${piccInfo.uid.toString('hex')}`);
console.log(`Counter: ${piccInfo.readCounterInt}`);
```

### 🔧 Express.js Integration
```javascript
const express = require('express');
const app = express();
const decoder = new NTAG424Crypto.Decoder(process.env.MASTER_KEY);

app.post('/api/nfc/verify', (req, res) => {
    const { nfcUrl } = req.body;
    const result = decoder.decrypt(nfcUrl);
    
    if (result.success && result.cmacValid) {
        res.json({
            authenticated: true,
            uid: result.uid,
            counter: result.readCounter,
            fileData: result.encryptedFileData
        });
    } else {
        res.status(400).json({
            authenticated: false,
            error: result.error
        });
    }
});
```

### 🔧 Batch Processing
```javascript
const decoder = new NTAG424Crypto.Decoder(masterKey);
const nfcUrls = ['url1', 'url2', 'url3']; // Array of NTAG424 URLs

const results = nfcUrls.map(url => {
    const result = decoder.decrypt(url);
    return {
        url,
        success: result.success,
        uid: result.uid,
        valid: result.cmacValid
    };
});

console.log(`Processed ${results.length} tags`);
console.log(`Valid: ${results.filter(r => r.success && r.valid).length}`);
```

### 🔧 Performance Monitoring
```javascript
const decoder = new NTAG424Crypto.Decoder(masterKey);

function monitoredDecrypt(nfcData) {
    const startTime = process.hrtime.bigint();
    const result = decoder.decrypt(nfcData);
    const endTime = process.hrtime.bigint();
    
    const duration = Number(endTime - startTime) / 1000000; // Convert to ms
    
    console.log(`Decryption took: ${duration.toFixed(2)}ms`);
    console.log(`Success: ${result.success}, CMAC Valid: ${result.cmacValid}`);
    
    return result;
}
```

## Installation

```bash
npm install node-aes-cmac
```

```javascript
const NTAG424Crypto = require('./ntag424-crypto');
```

## Quick Start

```javascript
// Initialize decoder with master key
const decoder = new NTAG424Crypto.Decoder('00112233445566778899AABBCCDDEEFF');

// Decrypt NTAG424 URL
const result = decoder.decrypt('https://example.com/nfc?picc_data=ABC123&cmac=DEF456');

if (result.success && result.cmacValid) {
    console.log(`UID: ${result.uid}, Counter: ${result.readCounter}`);
}
```

## Core Classes

### NTAG424Crypto.Decoder

Main decryption interface for NTAG424 data processing.

#### Constructor

```javascript
new NTAG424Crypto.Decoder(masterKey, options)
```

**Parameters:**
- `masterKey` (string): 32-character hex string (16 bytes)
- `options` (object, optional):
  - `keyDerivationMethod` (string): 'ntag424Official', 'hkdf', 'pbkdf2', 'simpleHash'
  - `sdmProfile` (string): 'uidOnly', 'counterOnly', 'uidCounter', 'full'
  - `validateCMAC` (boolean): Enable CMAC validation (default: true)
  - `strictValidation` (boolean): Enable strict input validation (default: false)

#### decrypt(input, customOptions)

Decrypt NTAG424 SDM data from URL, query string, or object.

**Parameters:**
- `input` (string|object): NTAG424 data in various formats
- `customOptions` (object, optional): Override default options

**Returns:**
```javascript
{
    success: boolean,
    uid: string,              // Hex string
    readCounter: number,      // Integer value
    dataTag: string,          // Hex string
    encryptedFileData: string, // Hex string (if present)
    cmacValid: boolean,
    sessionKeys: {
        encKey: string,
        macKey: string,
        derivationMethod: string
    },
    rawDecrypted: {
        picc: string,
        enc: string
    },
    error: string             // If success: false
}
```

## Key Derivation Methods

### NTAG424Crypto.KeyDerivation

#### ntag424Official(masterKey, uid, readCounter, options)

Official NXP NTAG424 key derivation using CMAC.

**Parameters:**
- `masterKey` (Buffer): 16-byte master key
- `uid` (Buffer): 7-byte tag UID
- `readCounter` (Buffer): 3-byte read counter
- `options` (object, optional):
  - `useCMAC` (boolean): Use CMAC for derivation (default: true)
  - `keyLength` (number): Key length in bytes (default: 16)

**Returns:**
```javascript
{
    encKey: Buffer,
    macKey: Buffer,
    method: string
}
```

#### hkdf(masterKey, uid, readCounter, options)

HMAC-based Key Derivation Function (RFC 5869).

**Parameters:**
- `masterKey` (Buffer): Master key for derivation
- `uid` (Buffer): Tag UID
- `readCounter` (Buffer): Read counter
- `options` (object, optional):
  - `algorithm` (string): Hash algorithm (default: 'sha256')
  - `salt` (Buffer): Custom salt (default: uid+counter)
  - `info` (string): Info string (default: 'NTAG424-SESSION-KEYS')
  - `keyLength` (number): Total key material length (default: 32)

#### pbkdf2(masterKey, uid, readCounter, options)

Password-Based Key Derivation Function 2 (RFC 2898).

**Parameters:**
- `masterKey` (Buffer): Master key for derivation
- `uid` (Buffer): Tag UID
- `readCounter` (Buffer): Read counter
- `options` (object, optional):
  - `iterations` (number): PBKDF2 iterations (default: 10000)
  - `algorithm` (string): Hash algorithm (default: 'sha256')
  - `saltPrefix` (string): Salt prefix (default: 'NTAG424')
  - `keyLength` (number): Total key material length (default: 32)

#### simpleHash(masterKey, uid, readCounter, options)

Fast hash-based key derivation for performance-critical applications.

**Parameters:**
- `masterKey` (Buffer): Master key for derivation
- `uid` (Buffer): Tag UID
- `readCounter` (Buffer): Read counter
- `options` (object, optional):
  - `algorithm` (string): Hash algorithm (default: 'sha256')
  - `keyLength` (number): Key length in bytes (default: 16)

## SDM Configuration

### NTAG424Crypto.SDMConfig

#### getProfile(profileName)

Get predefined SDM profile configuration.

**Parameters:**
- `profileName` (string): 'uidOnly', 'counterOnly', 'uidCounter', 'full'

**Returns:** SDM configuration object

#### createCustomProfile(config)

Create custom SDM profile for non-standard configurations.

**Parameters:**
- `config` (object): Custom configuration
  - `includeUID` (boolean): UID included in PICC data
  - `includeCounter` (boolean): Counter included in PICC data
  - `includeFileData` (boolean): Encrypted file data present
  - `piccDataLength` (number): PICC data block length
  - `uidOffset` (number): UID byte offset
  - `uidLength` (number): UID length in bytes
  - `counterOffset` (number): Counter byte offset
  - `counterLength` (number): Counter length in bytes

## AES Operations

### NTAG424Crypto.AES

#### cbcEncrypt(key, data, iv)

AES-128-CBC encryption with PKCS7 padding.

**Parameters:**
- `key` (Buffer): 16-byte AES key
- `data` (Buffer): Data to encrypt
- `iv` (Buffer, optional): 16-byte IV (default: zero IV)

**Returns:** Buffer (encrypted data)

#### cbcDecrypt(key, data, iv)

AES-128-CBC decryption with PKCS7 padding removal.

**Parameters:**
- `key` (Buffer): 16-byte AES key
- `data` (Buffer): Data to decrypt
- `iv` (Buffer, optional): 16-byte IV (default: zero IV)

**Returns:** Buffer (decrypted data)

#### ecbEncrypt(key, data)

AES-128-ECB encryption without padding (data must be 16-byte aligned).

#### ecbDecrypt(key, data)

AES-128-ECB decryption without padding.

## CMAC Operations

### NTAG424Crypto.CMAC

#### calculate(key, data)

Calculate AES-CMAC authentication code.

**Parameters:**
- `key` (Buffer): 16-byte AES key
- `data` (Buffer): Data to authenticate

**Returns:** Buffer (16-byte CMAC value)

#### verify(key, data, expectedMac)

Verify CMAC authenticity with constant-time comparison.

**Parameters:**
- `key` (Buffer): 16-byte AES key
- `data` (Buffer): Authenticated data
- `expectedMac` (Buffer): Expected CMAC value

**Returns:** boolean (true if valid)

## Data Parsing

### NTAG424Crypto.DataParser

#### parseURL(url)

Extract NTAG424 parameters from complete URL.

**Parameters:**
- `url` (string): Complete URL with NTAG424 parameters

**Returns:**
```javascript
{
    picc: string,
    enc: string,
    cmac: string,
    counter: string,
    originalUrl: string,
    baseUrl: string
}
```

#### parseQueryString(queryString)

Extract NTAG424 parameters from query string.

#### validateHexString(hexString, expectedLength)

Validate hexadecimal string format and length.

#### extractPiccData(decryptedPicc, sdmConfig)

Extract structured data from decrypted PICC according to SDM configuration.

**Returns:**
```javascript
{
    dataTag: number,
    uid: Buffer,
    readCounter: Buffer,
    readCounterInt: number,
    padding: Buffer,
    raw: Buffer
}
```

## Configuration Examples

### Basic Configuration

```javascript
const decoder = new NTAG424Crypto.Decoder('00112233445566778899AABBCCDDEEFF', {
    keyDerivationMethod: 'ntag424Official',
    sdmProfile: 'uidCounter',
    validateCMAC: true
});
```

### High-Security Configuration

```javascript
const decoder = new NTAG424Crypto.Decoder(masterKey, {
    keyDerivationMethod: 'hkdf',
    sdmProfile: 'full',
    validateCMAC: true,
    strictValidation: true
});
```

### Performance-Optimized Configuration

```javascript
const decoder = new NTAG424Crypto.Decoder(masterKey, {
    keyDerivationMethod: 'simpleHash',
    sdmProfile: 'uidCounter',
    validateCMAC: false
});
```

### Custom SDM Profile

```javascript
const customProfile = NTAG424Crypto.SDMConfig.createCustomProfile({
    includeUID: true,
    includeCounter: false,
    uidOffset: 2,
    uidLength: 6
});

const decoder = new NTAG424Crypto.Decoder(masterKey, {
    sdmProfile: customProfile
});
```

## Input Formats

### URL Format

```javascript
const result = decoder.decrypt('https://example.com/nfc?picc_data=ABC123&cmac=DEF456');
```

### Query String Format

```javascript
const result = decoder.decrypt('picc_data=ABC123&cmac=DEF456');
```

### Object Format

```javascript
const result = decoder.decrypt({
    picc: 'ABC123',
    enc: 'DEF456',
    cmac: '789ABC'
});
```

## Error Handling

```javascript
const result = decoder.decrypt(input);

if (!result.success) {
    console.error(`Decryption failed: ${result.error}`);
    return;
}

if (!result.cmacValid) {
    console.error('CMAC validation failed - data may be tampered');
    return;
}

// Process successful result
console.log(`UID: ${result.uid}, Counter: ${result.readCounter}`);
```

## Performance Considerations

- **Key Derivation Methods** (fastest to slowest):
  1. `simpleHash` - Fastest, suitable for high-throughput
  2. `ntag424Official` - Balanced performance and security
  3. `hkdf` - Strong security, moderate performance
  4. `pbkdf2` - Highest security, slowest due to iterations

- **SDM Profiles** (fastest to slowest):
  1. `uidOnly` - Minimal processing
  2. `counterOnly` - Minimal processing
  3. `uidCounter` - Standard processing
  4. `full` - Maximum processing (includes file data)

- **CMAC Validation**: Disable for performance-critical applications where data integrity is assured by other means

## Project Structure

```
ntag424-crypto/
├── package.json          ← Package configuration
├── ntag424-crypto.js     ← Main library
├── test.js               ← Simple test suite
├── README.md             ← This documentation
└── LICENSE               ← MIT License
```

## Author

**Serdar Tepekule** - [GitHub](https://github.com/serdartpkl)

## Repository

- **Source Code:** [github.com/serdartpkl/ntag424-crypto](https://github.com/serdartpkl/ntag424-crypto)
- **Issues:** [github.com/serdartpkl/ntag424-crypto/issues](https://github.com/serdartpkl/ntag424-crypto/issues)

## Dependencies

- **crypto** (Node.js built-in): Core cryptographic operations
- **node-aes-cmac** (required): Standards-compliant CMAC implementation

## License

MIT
