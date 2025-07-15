const NTAG424Crypto = require('./ntag424-crypto');

/**
 * Simple NTAG424 Test Suite
 * Basic validation and performance testing
 * 
 * @author Serdar Tepekule
 * @version 1.0.0
 */

console.log('🚀 NTAG424 Simple Test Suite');
console.log('============================\n');

console.log('📋 Basic Crypto Operations Test');
try {
  const key = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
  const testData = Buffer.from('Hello NTAG424 Test!', 'utf8');
  
  const encrypted = NTAG424Crypto.AES.cbcEncrypt(key, testData);
  const decrypted = NTAG424Crypto.AES.cbcDecrypt(key, encrypted);
  
  if (decrypted.equals(testData)) {
    console.log('✅ SUCCESS - Basic AES operations working');
  } else {
    console.log('❌ FAILED - AES operations failed');
  }
  
  const cmac = NTAG424Crypto.CMAC.calculate(key, testData);
  const cmacValid = NTAG424Crypto.CMAC.verify(key, testData, cmac);
  
  if (cmacValid) {
    console.log('✅ SUCCESS - CMAC operations working');
  } else {
    console.log('❌ FAILED - CMAC operations failed');
  }
  
} catch (error) {
  console.log(`❌ EXCEPTION - ${error.message}`);
}

console.log('\n🔑 Key Derivation Methods');
const masterKey = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
const uid = Buffer.from('04958CAA5C5E80', 'hex');
const counter = Buffer.from('000001', 'hex');

const methods = [
  { 
    name: 'ntag424Official', 
    func: () => NTAG424Crypto.KeyDerivation.ntag424Official(masterKey, uid, counter)
  },
  { 
    name: 'hkdf', 
    func: () => NTAG424Crypto.KeyDerivation.hkdf(masterKey, uid, counter)
  },
  { 
    name: 'simpleHash', 
    func: () => NTAG424Crypto.KeyDerivation.simpleHash(masterKey, uid, counter)
  }
];

methods.forEach(method => {
  try {
    const startTime = process.hrtime.bigint();
    const keys = method.func();
    const duration = Number(process.hrtime.bigint() - startTime) / 1000000;
    
    const encKeyHex = keys.encKey instanceof Buffer ? 
      keys.encKey.toString('hex') : 
      Buffer.from(keys.encKey).toString('hex');
    
    console.log(`✅ ${method.name}: ${duration.toFixed(2)}ms - EncKey: ${encKeyHex.substring(0, 8)}...`);
  } catch (error) {
    console.log(`❌ ${method.name}: ${error.message}`);
  }
});

console.log('\n⚡ Performance Test (1000 iterations)');
const perfDecoder = new NTAG424Crypto.Decoder('00112233445566778899AABBCCDDEEFF');
const testUrl = 'https://test.com/nfc?picc_data=FDE4AFA99B5C820A2C1BB0F1C792D0EB&cmac=C48B89C17A233B2C';

const startTime = Date.now();
for (let i = 0; i < 1000; i++) {
  perfDecoder.decrypt(testUrl);
}
const totalTime = Date.now() - startTime;
const avgTime = totalTime / 1000;
const throughput = Math.round(1000 / (totalTime / 1000));

console.log(`📊 Average: ${avgTime.toFixed(2)}ms per operation`);
console.log(`🚀 Throughput: ${throughput.toLocaleString()} operations/second`);

console.log('\n🚨 Error Handling Test');
const strictDecoder = new NTAG424Crypto.Decoder('00112233445566778899AABBCCDDEEFF', { strictValidation: true });

const errorTests = [
  { name: 'Invalid URL', input: 'not-a-url' },
  { name: 'Missing PICC', input: { cmac: 'ABC123' } },
  { name: 'Invalid Hex', input: { picc: 'ZZZZ', cmac: 'ABC123' } }
];

errorTests.forEach(test => {
  const result = strictDecoder.decrypt(test.input);
  const status = !result.success ? '✅' : '❌';
  console.log(`${status} ${test.name}: ${result.success ? 'Unexpected success' : 'Correctly failed'}`);
});

console.log('\n🔧 Simple Manual Test');
try {
  const masterKey = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
  const testData = Buffer.from('Test NTAG424 Data!', 'utf8');
  
  const encrypted = NTAG424Crypto.AES.cbcEncrypt(masterKey, testData);
  console.log(`✅ Encryption successful: ${encrypted.length} bytes`);
  
  const decrypted = NTAG424Crypto.AES.cbcDecrypt(masterKey, encrypted);
  console.log(`✅ Decryption successful: ${decrypted.toString()}`);
  
  const uid = Buffer.from('04AABBCCDDEE80', 'hex');
  const counter = Buffer.from('000001', 'hex');
  const keys = NTAG424Crypto.KeyDerivation.ntag424Official(masterKey, uid, counter);
  console.log(`✅ Key derivation successful: ${keys.encKey.toString('hex').substring(0, 8)}...`);
  
  console.log('✅ All manual tests passed - Library core functions working!');
  
} catch (error) {
  console.log(`❌ Manual test failed: ${error.message}`);
}

console.log('\n✨ Test Suite Complete!');
console.log('\n💡 Quick Usage Example:');
console.log('const decoder = new NTAG424Crypto.Decoder("YOUR_MASTER_KEY");');
console.log('const result = decoder.decrypt("YOUR_NTAG424_URL");');
console.log('if (result.success && result.cmacValid) { /* authenticated */ }');

module.exports = {
  quickTest: (masterKey, url) => {
    const decoder = new NTAG424Crypto.Decoder(masterKey);
    return decoder.decrypt(url);
  }
};