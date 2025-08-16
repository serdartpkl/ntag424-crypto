# NTAG424 Crypto Library

A production-ready Node.js library for NTAG424 DNA encryption and decryption operations. This enhanced version features fixed SDM profile validation, structured error handling, and improved security.

[![npm version](https://img.shields.io/npm/v/ntag424-crypto.svg)](https://www.npmjs.com/package/ntag424-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)

## 🚀 What's New in v2.0.0

### ✅ Fixed SDM Profile Validation Bug
- **File data encryption now properly requires 'full' profile**
- Clear error messages guide users to correct profile usage
- Prevents accidental misuse of profile capabilities

### ✅ Structured Error Handling
- Detailed error types: `ValidationError`, `EncryptionError`, `DecryptionError`, `SDMProfileError`, `SecurityError`
- Error context with field names, expected values, and troubleshooting tips
- Better debugging with comprehensive error information

### ✅ Enhanced Security
- Automatic memory clearing for sensitive cryptographic data
- Timing attack protection in CMAC operations
- Secure buffer management with cleanup on process exit
- Global memory management to prevent memory leaks

## 📦 Installation

```bash
npm install ntag424-crypto
```

### Dependencies
```bash
npm install node-aes-cmac
```

## 🏃 Quick Start

```javascript
const NTAG424Crypto = require('ntag424-crypto');

// Generate a secure master key
const masterKey = NTAG424Crypto.Encoder.generateMasterKey();

// Basic encryption (no file data)
const encrypted = NTAG424Crypto.Encoder.encrypt(masterKey, '04AABBCCDDEE80', 42);

// Create URL for NFC tag
const url = NTAG424Crypto.Encoder.generateURL(encrypted, 'https://example.com/nfc');

// Decrypt data
const decoder = new NTAG424Crypto.Decoder(masterKey);
const result = decoder.decrypt(url);

console.log('UID:', result.uid);
console.log('Counter:', result.readCounter);
console.log('Valid:', result.success && result.cmacValid);
```

## 🔐 File Data Encryption (NEW)

File data encryption requires the **'full' SDM profile**:

```javascript
// ✅ Correct: Use 'full' profile for file data
const encrypted = NTAG424Crypto.Encoder.encrypt(
  masterKey, 
  '04AABBCCDDEE80', 
  42, 
  'Secret message!',  // File data
  { sdmProfile: 'full' }
);

// Decrypt with 'full' profile
const decoder = new NTAG424Crypto.Decoder(masterKey, { sdmProfile: 'full' });
const result = decoder.decrypt(encrypted.encryptedData);

console.log('File Data:', result.encryptedFileData);
```

```javascript
// ❌ Wrong: This will now throw an error
try {
  NTAG424Crypto.Encoder.encrypt(
    masterKey, 
    '04AABBCCDDEE80', 
    42, 
    'Secret message!',
    { sdmProfile: 'uidCounter' }  // Wrong profile!
  );
} catch (error) {
  console.log(error.message);
  // "Profile 'uidCounter' does not support file data encryption. Use 'full' profile instead."
}
```

## 📋 SDM Profiles

| Profile | UID | Counter | File Data | Use Case |
|---------|-----|---------|-----------|----------|
| `uidOnly` | ✅ | ❌ | ❌ | Simple UID tracking |
| `counterOnly` | ❌ | ✅ | ❌ | Usage counting |
| `uidCounter` | ✅ | ✅ | ❌ | **Default** - Basic NFC tags |
| `full` | ✅ | ✅ | ✅ | **Required for file data** |

## 🛠 Detailed API Reference

### Encoder

#### `NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter, fileData, options)`

Encrypts NTAG424 data with comprehensive validation and proper SDM profile enforcement.

**Parameters:**

**`masterKey`** *(string, required)*
- 32-character hexadecimal string (16 bytes)
- Must contain only valid hex characters: `0-9`, `A-F` (case insensitive)
- Example: `'00112233445566778899AABBCCDDEEFF'`
- Generate with: `NTAG424Crypto.Encoder.generateMasterKey()`

**`uid`** *(string|Buffer, required)*
- **String format**: 14-character hex string (7 bytes)
  - Must start with `04` (NFC Type A identifier)
  - Example: `'04AABBCCDDEE80'`
- **Buffer format**: 7-byte Buffer
  - Example: `Buffer.from('04AABBCCDDEE80', 'hex')`

**`counter`** *(number|Buffer, required)*
- **Number format**: Integer between 0 and 16,777,215 (2^24 - 1)
  - Example: `42`, `1000`, `16777215`
- **Buffer format**: 3-byte Buffer
  - Example: `Buffer.from([0x00, 0x00, 0x2A])` (42 in hex)

**`fileData`** *(string|Buffer, optional)*
- **Only works with `sdmProfile: 'full'`**
- **String format**: UTF-8 text (any length)
  - Example: `'Welcome to our restaurant!'`
- **Buffer format**: Raw binary data
  - Example: `Buffer.from('Secret data', 'utf8')`
- **Set to `null` or omit** for no file data

**`options`** *(object, optional)*
- **`sdmProfile`** *(string)*
  - `'uidOnly'` - Only UID in encrypted data
  - `'counterOnly'` - Only counter in encrypted data  
  - `'uidCounter'` - UID + counter (default)
  - `'full'` - UID + counter + file data (**required for fileData**)
- **`keyDerivationMethod`** *(string)*
  - `'ntag424Official'` - NXP official CMAC-based (default)
  - `'hkdf'` - HMAC-based Key Derivation (RFC 5869)
  - `'pbkdf2'` - Password-Based Key Derivation (RFC 2898)
  - `'simpleHash'` - Simple hash-based derivation

**Returns:** *(Object)*
```javascript
{
  originalData: {
    uid: 'string',           // UID as uppercase hex
    scanCount: number,       // Counter as number
    masterKey: '[REDACTED]', // Hidden for security
    keyDerivationMethod: 'string',
    sdmProfile: 'string',
    fileData: 'string'       // Only if fileData provided
  },
  encryptedData: {
    picc: 'string',          // Encrypted PICC data (hex)
    cmac: 'string',          // CMAC authentication (hex)
    enc: 'string'            // Encrypted file data (hex, only if fileData)
  },
  metadata: {
    timestamp: 'string',     // ISO timestamp
    profileUsed: 'string',   // Profile name
    hasFileData: boolean     // Whether file data included
  }
}
```

**Examples:**

```javascript
// Basic encryption (no file data)
const basic = NTAG424Crypto.Encoder.encrypt(
  '00112233445566778899AABBCCDDEEFF',
  '04AABBCCDDEE80',
  42
);

// With file data (requires 'full' profile)
const withFile = NTAG424Crypto.Encoder.encrypt(
  masterKey,
  '04CAFE123456AB',
  100,
  'Restaurant menu: Today\'s special is pasta!',
  { sdmProfile: 'full' }
);

// Different key derivation method
const hkdf = NTAG424Crypto.Encoder.encrypt(
  masterKey,
  uid,
  counter,
  null,
  { keyDerivationMethod: 'hkdf' }
);

// Buffer inputs
const bufferInputs = NTAG424Crypto.Encoder.encrypt(
  masterKey,
  Buffer.from('04AABBCCDDEE80', 'hex'),     // UID as Buffer
  Buffer.from([0x00, 0x00, 0x2A]),          // Counter as Buffer (42)
  Buffer.from('Secret data', 'utf8'),       // File data as Buffer
  { sdmProfile: 'full' }
);
```

#### `NTAG424Crypto.Encoder.generateMasterKey(options)`

Generates a cryptographically secure master key.

**Parameters:**
- `options` *(object, optional)* - Reserved for future use

**Returns:** *(string)* - 32-character uppercase hex string

**Example:**
```javascript
const masterKey = NTAG424Crypto.Encoder.generateMasterKey();
console.log(masterKey); // "B4F2A891C7D3E56F1234567890ABCDEF"
```

#### `NTAG424Crypto.Encoder.generateURL(encryptedData, baseURL)`

Generates a complete URL from encrypted data.

**Parameters:**
- `encryptedData` *(object)* - Result from `encrypt()` method
- `baseURL` *(string)* - Base URL for the NFC tag

**Returns:** *(string)* - Complete URL with query parameters

**Example:**
```javascript
const url = NTAG424Crypto.Encoder.generateURL(
  encrypted, 
  'https://restaurant.com/menu'
);
// Result: "https://restaurant.com/menu?picc_data=ABC123...&cmac=DEF456&enc=789ABC..."
```

#### `NTAG424Crypto.Encoder.generateQueryString(encryptedData)`

Generates query string parameters from encrypted data.

**Parameters:**
- `encryptedData` *(object)* - Result from `encrypt()` method

**Returns:** *(string)* - Query string parameters

**Example:**
```javascript
const query = NTAG424Crypto.Encoder.generateQueryString(encrypted);
// Result: "picc_data=ABC123...&cmac=DEF456&enc=789ABC..."
```

### Decoder

#### `new NTAG424Crypto.Decoder(masterKey, options)`

Creates a new decoder instance for NTAG424 data decryption.

**Parameters:**

**`masterKey`** *(string, required)*
- Same format as encoder: 32-character hex string
- Must match the key used for encryption
- Example: `'00112233445566778899AABBCCDDEEFF'`

**`options`** *(object, optional)*
- **`sdmProfile`** *(string)* - Must match profile used for encryption
  - Default: `'uidCounter'`
  - Use `'full'` if encrypted data contains file data
- **`keyDerivationMethod`** *(string)* - Must match method used for encryption
  - Default: `'ntag424Official'`
- **`validateCMAC`** *(boolean)* - Enable CMAC validation
  - Default: `true` (recommended)
- **`strictValidation`** *(boolean)* - Enable strict input validation
  - Default: `false`
- **`timingAttackProtection`** *(boolean)* - Enable timing attack protection
  - Default: `true`

**Example:**
```javascript
// Basic decoder
const decoder = new NTAG424Crypto.Decoder(masterKey);

// Decoder for file data
const fullDecoder = new NTAG424Crypto.Decoder(masterKey, {
  sdmProfile: 'full'
});

// Decoder with custom options
const customDecoder = new NTAG424Crypto.Decoder(masterKey, {
  sdmProfile: 'uidCounter',
  keyDerivationMethod: 'hkdf',
  validateCMAC: true,
  strictValidation: true
});
```

#### `decoder.decrypt(input, customOptions)`

Decrypts NTAG424 data from various input formats.

**Parameters:**

**`input`** *(string|Object, required)*

**String formats:**
- **Complete URL**: `'https://example.com/nfc?picc_data=ABC123&cmac=DEF456'`
- **Query string**: `'picc_data=ABC123&cmac=DEF456&enc=789ABC'`

**Object format:**
```javascript
{
  picc: 'string',    // Encrypted PICC data (hex, required)
  cmac: 'string',    // CMAC authentication (hex, required)
  enc: 'string'      // Encrypted file data (hex, optional)
}
```

**`customOptions`** *(object, optional)*
- Override decoder options for this specific operation
- Same format as constructor options

**Returns:** *(Object)*
```javascript
{
  success: boolean,              // Whether decryption succeeded
  uid: 'string' | null,         // Extracted UID (hex, uppercase)
  readCounter: number | null,    // Read counter value
  dataTag: 'string' | null,     // Data tag (hex, usually 'C7')
  encryptedFileData: 'string' | null, // Decrypted file data (UTF-8)
  cmacValid: boolean,           // CMAC validation result
  sessionKeys: {
    encKey: 'string',           // Encryption key used (hex)
    macKey: 'string',           // MAC key used (hex)
    derivationMethod: 'string'  // Method used
  },
  rawDecrypted: {
    picc: 'string',             // Raw decrypted PICC (hex)
    enc: 'string' | null        // Raw decrypted file data (hex)
  },
  piccInfo: {
    dataTag: number,            // Data tag as number
    uid: Buffer | null,         // UID as Buffer
    readCounter: Buffer | null, // Counter as Buffer
    readCounterInt: number | null, // Counter as number
    padding: Buffer | null      // Padding data
  },
  metadata: {
    timestamp: 'string',        // ISO timestamp
    profileUsed: 'string'       // Profile used for decryption
  },
  performance: {
    duration: number            // Decryption time in ms
  },
  context: object,              // Operation context
  options: object,              // Options used
  
  // Error information (if success: false)
  error: 'string',              // Error message
  errorCode: 'string',          // Error code
  errorType: 'string',          // Error type name
  troubleshooting: string[]     // Troubleshooting tips
}
```

**Examples:**

```javascript
// Decrypt from URL
const urlResult = decoder.decrypt('https://example.com/nfc?picc_data=ABC123&cmac=DEF456');

// Decrypt from query string
const queryResult = decoder.decrypt('picc_data=ABC123&cmac=DEF456');

// Decrypt from object
const objectResult = decoder.decrypt({
  picc: 'ABC123...',
  cmac: 'DEF456...',
  enc: '789ABC...'  // Only for 'full' profile
});

// Decrypt with custom options
const customResult = decoder.decrypt(input, {
  sdmProfile: 'full',
  validateCMAC: false
});

// Check results
if (objectResult.success && objectResult.cmacValid) {
  console.log('✅ Decryption successful');
  console.log('UID:', objectResult.uid);
  console.log('Counter:', objectResult.readCounter);
  console.log('File Data:', objectResult.encryptedFileData);
} else {
  console.log('❌ Decryption failed:', objectResult.error);
  console.log('Troubleshooting:', objectResult.troubleshooting);
}
```

#### `decoder.destroy()`

Cleanup decoder resources and clear sensitive memory.

**Example:**
```javascript
const decoder = new NTAG424Crypto.Decoder(masterKey);
// ... use decoder
decoder.destroy(); // Clean up when done
```

## 🎯 Real-World Examples

### Restaurant Menu

```javascript
const restaurantKey = NTAG424Crypto.Encoder.generateMasterKey();
const menuData = 'Welcome to our restaurant! Today\'s special: Pasta!';

// Encrypt menu with file data
const encrypted = NTAG424Crypto.Encoder.encrypt(
  restaurantKey,
  '04CAFE123456AB',
  5,
  menuData,
  { sdmProfile: 'full' }
);

// Generate URL for NFC tag
const menuURL = NTAG424Crypto.Encoder.generateURL(
  encrypted, 
  'https://restaurant.com/menu'
);

// Customer scans tag - decrypt menu
const decoder = new NTAG424Crypto.Decoder(restaurantKey, { sdmProfile: 'full' });
const result = decoder.decrypt(menuURL);

console.log('Menu:', result.encryptedFileData);
console.log('Scan count:', result.readCounter);
```

### Product Authentication

```javascript
const productKey = NTAG424Crypto.Encoder.generateMasterKey();
const serialNumber = 'AUTHENTIC-PRODUCT-XYZ789';

// Encrypt product with authentication data
const encrypted = NTAG424Crypto.Encoder.encrypt(
  productKey,
  '04DEADBEEFCAFE',
  100,
  serialNumber,
  { sdmProfile: 'full' }
);

// Verify product authenticity
const decoder = new NTAG424Crypto.Decoder(productKey, { sdmProfile: 'full' });
const result = decoder.decrypt(encrypted.encryptedData);

if (result.success && result.cmacValid) {
  console.log('✅ AUTHENTIC PRODUCT');
  console.log('Serial:', result.encryptedFileData);
} else {
  console.log('❌ COUNTERFEIT PRODUCT');
}
```

### Basic Access Control

```javascript
const accessKey = NTAG424Crypto.Encoder.generateMasterKey();

// Simple UID + counter (no file data needed)
const encrypted = NTAG424Crypto.Encoder.encrypt(
  accessKey,
  '04ACCESS123456',
  42
  // No file data, no sdmProfile needed (defaults to 'uidCounter')
);

const decoder = new NTAG424Crypto.Decoder(accessKey);
const result = decoder.decrypt(encrypted.encryptedData);

if (result.success && result.cmacValid) {
  console.log('✅ ACCESS GRANTED');
  console.log('User ID:', result.uid);
  console.log('Usage count:', result.readCounter);
}
```

## 🔧 Error Handling

The library provides comprehensive structured error handling:

```javascript
try {
  const encrypted = NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter, fileData, options);
} catch (error) {
  console.log('Error Type:', error.name);
  console.log('Error Code:', error.code);
  console.log('Message:', error.message);
  console.log('Field:', error.details?.field);
  console.log('Expected:', error.details?.expected);
  console.log('Timestamp:', error.timestamp);
  
  // Handle specific error types
  switch (error.name) {
    case 'ValidationError':
      console.log('Fix your input parameters');
      break;
    case 'SDMProfileError':
      console.log('Use correct SDM profile');
      break;
    case 'EncryptionError':
      console.log('Check encryption settings');
      break;
    case 'SecurityError':
      console.log('Security issue detected');
      break;
  }
}
```

### Available Error Types

- **`ValidationError`** - Invalid input parameters
- **`EncryptionError`** - Encryption process failures  
- **`DecryptionError`** - Decryption process failures
- **`SDMProfileError`** - Profile compatibility issues
- **`SecurityError`** - Security-related problems

## 🧪 Testing

```bash
# Run comprehensive tests
npm test

# Run demo with examples
npm run demo
```

The test suite includes:
- ✅ Basic encryption/decryption functionality
- ✅ SDM profile validation fix verification
- ✅ Structured error handling tests
- ✅ Multiple key derivation methods
- ✅ URL and query string formats
- ✅ Performance benchmarks
- ✅ Real-world scenario testing

## ⚡ Performance

The library delivers excellent performance:
- **~1.5ms per operation** on modern hardware
- **600+ operations/second** throughput
- Efficient memory management with automatic cleanup
- Zero hardware dependencies
- Global memory management prevents memory leaks

## 🔒 Security Features

- **Memory Clearing**: Automatic cleanup of sensitive cryptographic data
- **Timing Attack Protection**: Constant-time operations in CMAC verification
- **Input Validation**: Comprehensive validation with detailed error messages
- **Secure Key Generation**: Cryptographically secure random key generation
- **Global Memory Management**: Prevents memory leaks in high-usage scenarios
- **Process Exit Cleanup**: Automatic memory clearing on application exit

## 🆕 Migration from v1.x

### Breaking Changes

1. **SDM Profile Validation**: File data now requires 'full' profile
2. **Error Types**: Changed from generic `Error` to structured error classes
3. **Import Paths**: Enhanced modules moved to `lib/` directory
4. **Memory Management**: Added automatic cleanup (no breaking changes to API)

### Migration Example

**Before (v1.x):**
```javascript
// This worked incorrectly in v1.x
const encrypted = Encoder.encrypt(masterKey, uid, counter, fileData); // Any profile
```

**After (v2.x):**
```javascript
// This now requires proper profile
const encrypted = Encoder.encrypt(masterKey, uid, counter, fileData, { 
  sdmProfile: 'full' 
});
```

## 📚 Key Derivation Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| `ntag424Official` | NXP official CMAC-based derivation | **Default** - Standards compliance |
| `hkdf` | HMAC-based Key Derivation (RFC 5869) | High-security applications |
| `pbkdf2` | Password-Based Key Derivation (RFC 2898) | Additional brute-force protection |
| `simpleHash` | Simple hash-based derivation | Performance-critical applications |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `npm test`
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🏷️ Version History

### v2.0.0 (Current)
- ✅ Fixed SDM profile validation bug
- ✅ Added structured error handling
- ✅ Enhanced security with memory management
- ✅ Improved performance and reliability
- ✅ Global memory management to prevent leaks
- ✅ Comprehensive test suite

### v1.0.0
- Initial release with basic NTAG424 functionality

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/serdartpkl/ntag424-crypto/issues)
- **Documentation**: This README and inline JSDoc comments
- **Examples**: See `simple-demo.js` for comprehensive examples
- **Tests**: Run `npm test` to see all functionality in action

## 🎯 Perfect For

- 🍽️ **Restaurant menus** with dynamic content
- 🏷️ **Product authentication** and anti-counterfeiting
- 🚪 **Access control** systems
- 🏭 **IoT device** authentication
- 📱 **NFC-enabled applications**
- 🔐 **Secure data transmission**

---

**Ready for production use with enhanced security and reliability!** 🚀readCounter);
```

### Product Authentication

```javascript
const productKey = NTAG424Crypto.Encoder.generateMasterKey();
const serialNumber = 'AUTHENTIC-PRODUCT-XYZ789';

// Encrypt product with authentication data
const encrypted = NTAG424Crypto.Encoder.encrypt(
  productKey,
  '04DEADBEEFCAFE',
  100,
  serialNumber,
  { sdmProfile: 'full' }
);

// Verify product authenticity
const decoder = new NTAG424Crypto.Decoder(productKey, { sdmProfile: 'full' });
const result = decoder.decrypt(encrypted.encryptedData);

if (result.success && result.cmacValid) {
  console.log('✅ AUTHENTIC PRODUCT');
  console.log('Serial:', result.encryptedFileData);
} else {
  console.log('❌ COUNTERFEIT PRODUCT');
}
```

### Basic Access Control

```javascript
const accessKey = NTAG424Crypto.Encoder.generateMasterKey();

// Simple UID + counter (no file data needed)
const encrypted = NTAG424Crypto.Encoder.encrypt(
  accessKey,
  '04ACCESS123456',
  42
  // No file data, no sdmProfile needed (defaults to 'uidCounter')
);

const decoder = new NTAG424Crypto.Decoder(accessKey);
const result = decoder.decrypt(encrypted.encryptedData);

if (result.success && result.cmacValid) {
  console.log('✅ ACCESS GRANTED');
  console.log('User ID:', result.uid);
  console.log('Usage count:', result.readCounter);
}
```

## 🔧 Error Handling

The library provides comprehensive structured error handling:

```javascript
try {
  const encrypted = NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter, fileData, options);
} catch (error) {
  console.log('Error Type:', error.name);
  console.log('Error Code:', error.code);
  console.log('Message:', error.message);
  console.log('Field:', error.details?.field);
  console.log('Expected:', error.details?.expected);
  console.log('Timestamp:', error.timestamp);
  
  // Handle specific error types
  switch (error.name) {
    case 'ValidationError':
      console.log('Fix your input parameters');
      break;
    case 'SDMProfileError':
      console.log('Use correct SDM profile');
      break;
    case 'EncryptionError':
      console.log('Check encryption settings');
      break;
    case 'SecurityError':
      console.log('Security issue detected');
      break;
  }
}
```

### Available Error Types

- **`ValidationError`** - Invalid input parameters
- **`EncryptionError`** - Encryption process failures  
- **`DecryptionError`** - Decryption process failures
- **`SDMProfileError`** - Profile compatibility issues
- **`SecurityError`** - Security-related problems

## 🧪 Testing

```bash
# Run comprehensive tests
npm test

# Run demo with examples
npm run demo
```

The test suite includes:
- ✅ Basic encryption/decryption functionality
- ✅ SDM profile validation fix verification
- ✅ Structured error handling tests
- ✅ Multiple key derivation methods
- ✅ URL and query string formats
- ✅ Performance benchmarks
- ✅ Real-world scenario testing

## ⚡ Performance

The library delivers excellent performance:
- **~1.5ms per operation** on modern hardware
- **600+ operations/second** throughput
- Efficient memory management with automatic cleanup
- Zero hardware dependencies
- Global memory management prevents memory leaks

## 🔒 Security Features

- **Memory Clearing**: Automatic cleanup of sensitive cryptographic data
- **Timing Attack Protection**: Constant-time operations in CMAC verification
- **Input Validation**: Comprehensive validation with detailed error messages
- **Secure Key Generation**: Cryptographically secure random key generation
- **Global Memory Management**: Prevents memory leaks in high-usage scenarios
- **Process Exit Cleanup**: Automatic memory clearing on application exit

## 🆕 Migration from v1.x

### Breaking Changes

1. **SDM Profile Validation**: File data now requires 'full' profile
2. **Error Types**: Changed from generic `Error` to structured error classes
3. **Import Paths**: Enhanced modules moved to `lib/` directory
4. **Memory Management**: Added automatic cleanup (no breaking changes to API)

### Migration Example

**Before (v1.x):**
```javascript
// This worked incorrectly in v1.x
const encrypted = Encoder.encrypt(masterKey, uid, counter, fileData); // Any profile
```

**After (v2.x):**
```javascript
// This now requires proper profile
const encrypted = Encoder.encrypt(masterKey, uid, counter, fileData, { 
  sdmProfile: 'full' 
});
```

## 📚 Key Derivation Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| `ntag424Official` | NXP official CMAC-based derivation | **Default** - Standards compliance |
| `hkdf` | HMAC-based Key Derivation (RFC 5869) | High-security applications |
| `pbkdf2` | Password-Based Key Derivation (RFC 2898) | Additional brute-force protection |
| `simpleHash` | Simple hash-based derivation | Performance-critical applications |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `npm test`
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🏷️ Version History

### v2.0.0 (Current)
- ✅ Fixed SDM profile validation bug
- ✅ Added structured error handling
- ✅ Enhanced security with memory management
- ✅ Improved performance and reliability
- ✅ Global memory management to prevent leaks
- ✅ Comprehensive test suite

### v1.0.0
- Initial release with basic NTAG424 functionality

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/serdartpkl/ntag424-crypto/issues)
- **Documentation**: This README and inline JSDoc comments
- **Examples**: See `simple-demo.js` for comprehensive examples
- **Tests**: Run `npm test` to see all functionality in action

## 🎯 Perfect For

- 🍽️ **Restaurant menus** with dynamic content
- 🏷️ **Product authentication** and anti-counterfeiting
- 🚪 **Access control** systems
- 🏭 **IoT device** authentication
- 📱 **NFC-enabled applications**
- 🔐 **Secure data transmission**

---

**Ready for production use with enhanced security and reliability!** 🚀
