# NTAG424 Crypto Library

A production-ready Node.js library for NTAG424 DNA encryption and decryption operations. This library provides complete cryptographic functionality for NTAG424 tags without hardware dependencies, designed for server-side processing and validation.

## Features

- **Zero Vector Decryption** - Compatible with standard NTAG424 implementations
- **Secure Master Key Generation** - Cryptographically secure random key generation
- **Multiple Output Formats** - Object, URL, and query string formats
- **File Data Encryption** - Support for encrypted file data (ENC parameter)
- **Multiple Key Derivation Methods** - NTAG424 official, HKDF, PBKDF2, and simple hash
- **Configurable SDM Profiles** - Support for different Secure Dynamic Messaging configurations
- **CMAC Authentication** - Data integrity and authenticity verification
- **High Performance** - 1000+ operations per second
- **Zero Dependencies** - Only requires Node.js built-in crypto and node-aes-cmac

## Installation

```bash
npm install ntag424-crypto
```

### Dependencies

```bash
npm install node-aes-cmac
```

## Quick Start

```javascript
const NTAG424Crypto = require('ntag424-crypto');

// Generate a secure master key
const masterKey = NTAG424Crypto.Encoder.generateMasterKey();

// Encrypt data
const encrypted = NTAG424Crypto.Encoder.encrypt(masterKey, '04AABBCCDDEE80', 42);

// Generate URL for NFC tag
const url = NTAG424Crypto.Encoder.generateURL(encrypted, 'https://example.com/nfc');

// Decrypt data
const decoder = new NTAG424Crypto.Decoder(masterKey);
const result = decoder.decrypt(url);

console.log('UID:', result.uid);
console.log('Counter:', result.readCounter);
console.log('Valid:', result.success && result.cmacValid);
```

## API Documentation

### Encoder

#### `NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter, fileData, options)`

Encrypts data using NTAG424 algorithms.

**Parameters:**
- `masterKey` (string) - 32-character hexadecimal master key
- `uid` (string|Buffer) - 7-byte UID as 14-character hex string or Buffer
- `counter` (number|Buffer) - Scan counter (0-16777215) or 3-byte Buffer
- `fileData` (string|Buffer, optional) - File data to encrypt
- `options` (object, optional) - Configuration options
  - `keyDerivationMethod` (string) - 'ntag424Official' (default), 'hkdf', 'pbkdf2', 'simpleHash'
  - `sdmProfile` (string) - 'uidCounter' (default), 'uidOnly', 'counterOnly', 'full'

**Returns:** Object with `originalData` and `encryptedData` properties

**Example:**
```javascript
const result = NTAG424Crypto.Encoder.encrypt(
  '00112233445566778899AABBCCDDEEFF',
  '04AABBCCDDEE80',
  42,
  'Secret data'
);
```

#### `NTAG424Crypto.Encoder.generateMasterKey(options)`

Generates a cryptographically secure master key.

**Parameters:**
- `options` (object, optional) - Generation options

**Returns:** 32-character hexadecimal string

**Example:**
```javascript
const masterKey = NTAG424Crypto.Encoder.generateMasterKey();
```

#### `NTAG424Crypto.Encoder.generateURL(encryptedData, baseURL)`

Generates a complete URL from encrypted data.

**Parameters:**
- `encryptedData` (object) - Result from `encrypt()` method
- `baseURL` (string) - Base URL for the NFC tag

**Returns:** Complete URL string

**Example:**
```javascript
const url = NTAG424Crypto.Encoder.generateURL(encrypted, 'https://example.com/nfc');
```

#### `NTAG424Crypto.Encoder.generateQueryString(encryptedData)`

Generates query string parameters from encrypted data.

**Parameters:**
- `encryptedData` (object) - Result from `encrypt()` method

**Returns:** Query string

**Example:**
```javascript
const query = NTAG424Crypto.Encoder.generateQueryString(encrypted);
```

### Decoder

#### `new NTAG424Crypto.Decoder(masterKey, options)`

Creates a new decoder instance.

**Parameters:**
- `masterKey` (string) - 32-character hexadecimal master key
- `options` (object, optional) - Configuration options
  - `keyDerivationMethod` (string) - 'ntag424Official' (default), 'hkdf', 'pbkdf2', 'simpleHash'
  - `sdmProfile` (string) - 'uidCounter' (default), 'uidOnly', 'counterOnly', 'full'
  - `validateCMAC` (boolean) - Enable CMAC validation (default: true)
  - `strictValidation` (boolean) - Enable strict input validation (default: false)

**Example:**
```javascript
const decoder = new NTAG424Crypto.Decoder('00112233445566778899AABBCCDDEEFF');
```

#### `decoder.decrypt(input, customOptions)`

Decrypts NTAG424 data.

**Parameters:**
- `input` (string|object) - URL, query string, or object with encrypted data
- `customOptions` (object, optional) - Override options for this operation

**Returns:** Decryption result object
- `success` (boolean) - Whether decryption succeeded
- `uid` (string) - Extracted UID as hex string
- `readCounter` (number) - Read counter value
- `dataTag` (string) - Data tag as hex string
- `cmacValid` (boolean) - CMAC validation result
- `encryptedFileData` (string) - Decrypted file data (if present)
- `sessionKeys` (object) - Generated session keys
- `error` (string) - Error message if decryption failed

**Example:**
```javascript
const result = decoder.decrypt('https://example.com/nfc?picc_data=ABC123&cmac=DEF456');

if (result.success && result.cmacValid) {
  console.log('UID:', result.uid);
  console.log('Counter:', result.readCounter);
} else {
  console.error('Decryption failed:', result.error);
}
```

## SDM Profiles

The library supports different Secure Dynamic Messaging profiles:

### Predefined Profiles

- **`uidOnly`** - Only UID in encrypted data
- **`counterOnly`** - Only counter in encrypted data  
- **`uidCounter`** - Both UID and counter (default)
- **`full`** - UID, counter, and file data

### Custom SDM Profiles

You can create custom SDM profiles for specialized NTAG424 configurations:

```javascript
const customProfile = NTAG424Crypto.SDMConfig.createCustomProfile({
  includeUID: true,
  includeCounter: false,
  includeFileData: true,
  piccDataLength: 16,
  uidOffset: 2,
  uidLength: 6,
  encFileDataLength: 32
});

const encrypted = NTAG424Crypto.Encoder.encrypt(
  masterKey, 
  uid, 
  counter, 
  fileData,
  { sdmProfile: customProfile }
);

const decoder = new NTAG424Crypto.Decoder(masterKey, { 
  sdmProfile: customProfile 
});
```

### Custom Profile Parameters

- `includeUID` (boolean) - Whether UID is included in PICC data
- `includeCounter` (boolean) - Whether counter is included in PICC data
- `includeFileData` (boolean) - Whether encrypted file data is present
- `piccDataLength` (number) - Length of PICC data block (default: 16)
- `uidOffset` (number) - Byte offset of UID in PICC data (default: 1)
- `uidLength` (number) - Length of UID in bytes (default: 7)
- `counterOffset` (number) - Byte offset of counter in PICC data (default: 8)
- `counterLength` (number) - Length of counter in bytes (default: 3)
- `encFileDataLength` (number) - Length of encrypted file data (default: 16)

### Profile Validation

Validate custom profiles before use:

```javascript
const validation = NTAG424Crypto.SDMConfig.validateProfile(customProfile);
if (!validation.isValid) {
  console.error('Profile errors:', validation.errors);
}
```

### Available Profiles

Get a list of all predefined profiles:

```javascript
const profiles = NTAG424Crypto.SDMConfig.getAvailableProfiles();
console.log('Available profiles:', profiles);
```

## Key Derivation Methods

Four key derivation methods are supported:

- **`ntag424Official`** - Official NTAG424 CMAC-based derivation (default)
- **`hkdf`** - HMAC-based Key Derivation Function (RFC 5869)
- **`pbkdf2`** - Password-Based Key Derivation Function 2 (RFC 2898)
- **`simpleHash`** - Simple hash-based derivation

## Error Handling

All methods provide comprehensive error handling:

```javascript
try {
  const result = decoder.decrypt(input);
  if (!result.success) {
    console.error('Decryption failed:', result.error);
  }
} catch (error) {
  console.error('Library error:', error.message);
}
```

## Data Formats

### Input Formats

The decoder accepts multiple input formats:

**URL Format:**
```
https://example.com/nfc?picc_data=ABC123&cmac=DEF456
```

**Query String:**
```
picc_data=ABC123&cmac=DEF456
```

**Object Format:**
```javascript
{
  picc: 'ABC123',
  cmac: 'DEF456',
  enc: 'optional_file_data'
}
```

### UID Format

UIDs must be exactly 14 hexadecimal characters (7 bytes):
- Must start with `04` (NFC Type A identifier)
- Remaining 12 characters must be valid hex (0-9, A-F)
- Example: `04AABBCCDDEE80`

## Performance

The library is optimized for high performance:
- 1000+ encrypt/decrypt operations per second
- Zero hardware dependencies
- Minimal memory footprint
- Efficient zero vector implementation

## Security

- CMAC authentication for data integrity
- Cryptographically secure key generation
- Protection against timing attacks
- Validation of all input parameters

## Usage

### Basic Operations

```javascript
// Generate master key
const masterKey = NTAG424Crypto.Encoder.generateMasterKey();

// Encrypt data
const encrypted = NTAG424Crypto.Encoder.encrypt(masterKey, '04AABBCCDDEE80', 42);

// Create decoder
const decoder = new NTAG424Crypto.Decoder(masterKey);

// Decrypt data
const result = decoder.decrypt(encrypted.encryptedData);
```

### URL Generation

```javascript
// Generate URL from encrypted data
const url = NTAG424Crypto.Encoder.generateURL(encrypted, 'https://example.com/nfc');

// Generate query string only
const query = NTAG424Crypto.Encoder.generateQueryString(encrypted);
```

### File Data Encryption

```javascript
// Encrypt with file data
const withFileData = NTAG424Crypto.Encoder.encrypt(
  masterKey, 
  '04AABBCCDDEE80', 
  42, 
  'Secret file content'
);

// Decrypt with file data support
const decoder = new NTAG424Crypto.Decoder(masterKey, { sdmProfile: 'full' });
const result = decoder.decrypt({
  picc: withFileData.encryptedData.picc,
  enc: withFileData.encryptedData.enc,
  cmac: withFileData.encryptedData.cmac
});
```

### Custom SDM Profile

```javascript
// Create custom profile
const customProfile = NTAG424Crypto.SDMConfig.createCustomProfile({
  includeUID: true,
  includeCounter: false,
  uidOffset: 2,
  uidLength: 6
});

// Use custom profile
const encrypted = NTAG424Crypto.Encoder.encrypt(
  masterKey, 
  uid, 
  counter, 
  null,
  { sdmProfile: customProfile }
);
```

### Different Key Methods

```javascript
// Use HKDF key derivation
const hkdfEncrypted = NTAG424Crypto.Encoder.encrypt(
  masterKey, 
  uid, 
  counter, 
  null,
  { keyDerivationMethod: 'hkdf' }
);

const hkdfDecoder = new NTAG424Crypto.Decoder(masterKey, { 
  keyDerivationMethod: 'hkdf' 
});
```

### Error Handling

```javascript
// Basic error handling
const result = decoder.decrypt(input);
if (!result.success) {
  console.error('Error:', result.error);
} else if (!result.cmacValid) {
  console.error('CMAC validation failed');
} else {
  console.log('Success:', result.uid, result.readCounter);
}
```

## Testing

Run the comprehensive test suite:

```bash
node comprehensive-test.js
```

Run the demo:

```bash
node simple-demo.js
```

## Compatibility

- **Node.js**: 14.0.0 or higher
- **NTAG424 DNA**: Compatible with standard zero vector implementations
- **NFC**: Works with any NFC-enabled device that can read NTAG424 tags

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests to ensure they pass
5. Submit a pull request

## Support

For issues and questions:
- Check the comprehensive test suite for usage examples
- Review the simple demo for practical implementations
- Open an issue on the repository for bugs or feature requests

## Changelog

### v1.0.0
- Initial release
- Zero vector implementation
- Multiple key derivation methods
- Comprehensive SDM profile support
- High performance optimization
- Complete test coverage
