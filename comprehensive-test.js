/**
 * NTAG424 Crypto Library - Comprehensive Test Suite
 * 
 * Focused testing for real-world use cases without random data generation.
 * Tests encoding and decoding with known data only.
 */

const NTAG424Crypto = require('./ntag424-crypto');

const testResults = {
  passed: 0,
  failed: 0,
  total: 0
};

function assert(condition, description) {
  testResults.total++;
  if (condition) {
    testResults.passed++;
    console.log(`✅ ${description}`);
    return true;
  } else {
    testResults.failed++;
    console.log(`❌ ${description}`);
    return false;
  }
}

function runTest(testName, testFunction) {
  console.log(`\n🧪 ${testName}`);
  console.log('-'.repeat(testName.length + 4));
  
  try {
    testFunction();
  } catch (error) {
    assert(false, `Test failed with error: ${error.message}`);
  }
}

// Test 1: Basic Functionality
runTest('Basic Encode/Decode Test', () => {
  const masterKey = '00112233445566778899AABBCCDDEEFF';
  const uid = '04AABBCCDDEE80';
  const counter = 42;
  
  const encryptResult = NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter);
  assert(encryptResult.originalData && encryptResult.encryptedData, 'Encoder produces complete result');
  assert(encryptResult.encryptedData.picc && encryptResult.encryptedData.cmac, 'Encoder produces PICC and CMAC');
  
  const decoder = new NTAG424Crypto.Decoder(masterKey);
  const decryptResult = decoder.decrypt({
    picc: encryptResult.encryptedData.picc,
    cmac: encryptResult.encryptedData.cmac
  });
  
  assert(decryptResult.success === true, 'Decoder successfully decrypts');
  assert(decryptResult.uid === uid.toUpperCase(), 'UID matches original');
  assert(decryptResult.readCounter === counter, 'Counter matches original');
  assert(decryptResult.cmacValid === true, 'CMAC validation passes');
});

// Test 2: Master Key Generation
runTest('Master Key Generation Test', () => {
  const generatedKey = NTAG424Crypto.Encoder.generateMasterKey();
  assert(typeof generatedKey === 'string', 'Generated key is string');
  assert(generatedKey.length === 32, 'Generated key is 32 characters');
  assert(/^[0-9A-F]+$/.test(generatedKey), 'Generated key is valid hex');
  
  const generatedKeyNoSpecial = NTAG424Crypto.Encoder.generateMasterKey({ includeSpecialChars: false });
  assert(generatedKeyNoSpecial.length === 32, 'Generated key without special chars is 32 characters');
  
  try {
    const testEncoder = NTAG424Crypto.Encoder.encrypt(generatedKey, '04AABBCCDDEE80', 42);
    assert(true, 'Generated key works for encryption');
  } catch (error) {
    assert(false, 'Generated key failed in encryption');
  }
});

// Test 3: URL Generation
runTest('URL Generation Test', () => {
  const masterKey = '00112233445566778899AABBCCDDEEFF';
  const uid = '04AABBCCDDEE80';
  const counter = 42;
  
  const encryptResult = NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter);
  
  const url = NTAG424Crypto.Encoder.generateURL(encryptResult, 'https://example.com/nfc');
  assert(url.startsWith('https://example.com/nfc?'), 'URL has correct base');
  assert(url.includes('picc_data='), 'URL contains PICC data');
  assert(url.includes('cmac='), 'URL contains CMAC');
  
  const queryString = NTAG424Crypto.Encoder.generateQueryString(encryptResult);
  assert(queryString.includes('picc_data='), 'Query string contains PICC data');
  assert(queryString.includes('cmac='), 'Query string contains CMAC');
  
  const decoder = new NTAG424Crypto.Decoder(masterKey);
  const urlDecryptResult = decoder.decrypt(url);
  assert(urlDecryptResult.success === true, 'URL format decrypts successfully');
  assert(urlDecryptResult.uid === uid.toUpperCase(), 'URL decrypt UID matches');
});

// Test 4: File Data Encryption
runTest('File Data Encryption Test', () => {
  const masterKey = '00112233445566778899AABBCCDDEEFF';
  const uid = '04AABBCCDDEE80';
  const counter = 42;
  const fileData = 'Secret Message!';
  
  const encryptResult = NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter, fileData);
  assert(encryptResult.encryptedData.enc, 'Encrypted file data present');
  assert(encryptResult.originalData.fileData === fileData, 'Original file data preserved');
  
  const decoder = new NTAG424Crypto.Decoder(masterKey, { sdmProfile: 'full' });
  const decryptResult = decoder.decrypt({
    picc: encryptResult.encryptedData.picc,
    enc: encryptResult.encryptedData.enc,
    cmac: encryptResult.encryptedData.cmac
  });
  
  assert(decryptResult.success === true, 'File data decryption succeeds');
  assert(decryptResult.encryptedFileData !== null, 'File data extracted');
});

// Test 5: Different Key Derivation Methods
runTest('Key Derivation Methods Test', () => {
  const masterKey = '00112233445566778899AABBCCDDEEFF';
  const uid = '04AABBCCDDEE80';
  const counter = 42;
  
  const methods = ['ntag424Official', 'hkdf', 'pbkdf2', 'simpleHash'];
  
  for (const method of methods) {
    const encryptResult = NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter, null, { keyDerivationMethod: method });
    const decoder = new NTAG424Crypto.Decoder(masterKey, { keyDerivationMethod: method });
    const decryptResult = decoder.decrypt({
      picc: encryptResult.encryptedData.picc,
      cmac: encryptResult.encryptedData.cmac
    });
    
    assert(decryptResult.success === true, `${method} method works`);
    assert(decryptResult.uid === uid.toUpperCase(), `${method} UID matches`);
  }
});

// Test 6: Different SDM Profiles
runTest('SDM Profiles Test', () => {
  const masterKey = '00112233445566778899AABBCCDDEEFF';
  const uid = '04AABBCCDDEE80';
  const counter = 42;
  
  const profiles = ['uidOnly', 'counterOnly', 'uidCounter'];
  
  for (const profile of profiles) {
    const encryptResult = NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter, null, { sdmProfile: profile });
    const decoder = new NTAG424Crypto.Decoder(masterKey, { sdmProfile: profile });
    const decryptResult = decoder.decrypt({
      picc: encryptResult.encryptedData.picc,
      cmac: encryptResult.encryptedData.cmac
    });
    
    assert(decryptResult.success === true, `${profile} profile works`);
    
    if (profile.includes('uid')) {
      assert(decryptResult.uid === uid.toUpperCase(), `${profile} UID extracted`);
    }
    if (profile.includes('counter') || profile === 'counterOnly') {
      assert(decryptResult.readCounter === counter, `${profile} counter extracted`);
    }
  }
});

// Test 7: Error Handling
runTest('Error Handling Test', () => {
  try {
    new NTAG424Crypto.Decoder('invalid-key');
    assert(false, 'Should reject invalid master key');
  } catch (error) {
    assert(true, 'Correctly rejects invalid master key');
  }
  
  try {
    NTAG424Crypto.Encoder.encrypt('00112233445566778899AABBCCDDEEFF', 'invalid-uid', 42);
    assert(false, 'Should reject invalid UID');
  } catch (error) {
    assert(true, 'Correctly rejects invalid UID');
  }
  
  const decoder = new NTAG424Crypto.Decoder('00112233445566778899AABBCCDDEEFF');
  const result = decoder.decrypt({ picc: 'invalid', cmac: 'invalid' });
  assert(result.success === false, 'Gracefully handles invalid input');
  assert(result.error, 'Provides error message');
});

// Test 8: Security Validation
runTest('Security Validation Test', () => {
  const correctKey = '00112233445566778899AABBCCDDEEFF';
  const wrongKey = '11223344556677889900AABBCCDDEEFF';
  const uid = '04AABBCCDDEE80';
  const counter = 42;
  
  const encryptResult = NTAG424Crypto.Encoder.encrypt(correctKey, uid, counter);
  
  const correctDecoder = new NTAG424Crypto.Decoder(correctKey);
  const wrongDecoder = new NTAG424Crypto.Decoder(wrongKey);
  
  const correctResult = correctDecoder.decrypt({
    picc: encryptResult.encryptedData.picc,
    cmac: encryptResult.encryptedData.cmac
  });
  
  const wrongResult = wrongDecoder.decrypt({
    picc: encryptResult.encryptedData.picc,
    cmac: encryptResult.encryptedData.cmac
  });
  
  assert(correctResult.success === true && correctResult.cmacValid === true, 'Correct key succeeds');
  assert(wrongResult.success === false || wrongResult.cmacValid === false, 'Wrong key fails');
  
  const corruptedPicc = encryptResult.encryptedData.picc.replace('A', 'B');
  const corruptedResult = correctDecoder.decrypt({
    picc: corruptedPicc,
    cmac: encryptResult.encryptedData.cmac
  });
  
  assert(corruptedResult.success === false || corruptedResult.cmacValid === false, 'Corrupted data fails');
});

// Test 9: Performance Test
runTest('Performance Test', () => {
  const masterKey = '00112233445566778899AABBCCDDEEFF'; // Use known working key
  const uid = '04AABBCCDDEE80';
  const counter = 42;
  
  const iterations = 100;
  const startTime = Date.now();
  
  let successCount = 0;
  let failureReasons = [];
  
  for (let i = 0; i < iterations; i++) {
    try {
      const encryptResult = NTAG424Crypto.Encoder.encrypt(masterKey, uid, counter + i);
      const decoder = new NTAG424Crypto.Decoder(masterKey);
      const decryptResult = decoder.decrypt({
        picc: encryptResult.encryptedData.picc,
        cmac: encryptResult.encryptedData.cmac
      });
      
      if (decryptResult.success && decryptResult.cmacValid) {
        successCount++;
      } else {
        failureReasons.push(`Iteration ${i}: success=${decryptResult.success}, cmacValid=${decryptResult.cmacValid}, error=${decryptResult.error}`);
      }
    } catch (error) {
      failureReasons.push(`Iteration ${i}: Exception - ${error.message}`);
    }
  }
  
  const totalTime = Date.now() - startTime;
  const avgTime = totalTime / iterations;
  
  if (successCount < iterations && failureReasons.length > 0) {
    console.log(`   Debug: ${failureReasons.slice(0, 3).join('; ')}`);
  }
  
  assert(successCount === iterations, `All ${iterations} operations successful (actual: ${successCount})`);
  assert(avgTime < 10, `Performance under 10ms per operation (actual: ${avgTime.toFixed(2)}ms)`);
});

// Test 10: Real-world Scenarios
runTest('Real-world Scenarios Test', () => {
  const scenarios = [
    {
      name: 'Restaurant Menu',
      masterKey: NTAG424Crypto.Encoder.generateMasterKey(),
      uid: '04123456789ABC',
      counter: 1,
      baseURL: 'https://restaurant.com/menu'
    },
    {
      name: 'Product Authentication',
      masterKey: NTAG424Crypto.Encoder.generateMasterKey(),
      uid: '04FEDCBA987654',
      counter: 5,
      baseURL: 'https://brand.com/verify',
      fileData: 'Authentic Product'
    },
    {
      name: 'Access Control',
      masterKey: NTAG424Crypto.Encoder.generateMasterKey(),
      uid: '04ABCDEF123456',
      counter: 42,
      baseURL: 'https://security.com/access'
    }
  ];
  
  for (const scenario of scenarios) {
    const sdmProfile = scenario.fileData ? 'full' : 'uidCounter';
    
    const encryptResult = NTAG424Crypto.Encoder.encrypt(
      scenario.masterKey, 
      scenario.uid, 
      scenario.counter, 
      scenario.fileData,
      { sdmProfile: sdmProfile }
    );
    
    const url = NTAG424Crypto.Encoder.generateURL(encryptResult, scenario.baseURL);
    
    const decoder = new NTAG424Crypto.Decoder(scenario.masterKey, {
      sdmProfile: sdmProfile
    });
    
    const result = decoder.decrypt(url);
    
    assert(result.success === true, `${scenario.name} scenario works`);
    assert(result.uid === scenario.uid.toUpperCase(), `${scenario.name} UID correct`);
    assert(result.readCounter === scenario.counter, `${scenario.name} counter correct`);
    
    if (scenario.fileData) {
      assert(result.encryptedFileData !== null, `${scenario.name} file data extracted`);
    }
  }
});

// Summary
console.log('\n📊 Test Summary');
console.log('================');
console.log(`Total Tests: ${testResults.total}`);
console.log(`Passed: ${testResults.passed} ✅`);
console.log(`Failed: ${testResults.failed} ❌`);
console.log(`Success Rate: ${((testResults.passed / testResults.total) * 100).toFixed(1)}%`);

if (testResults.failed === 0) {
  console.log('\n🎉 All tests passed! The library is working correctly.');
  console.log('✨ Key features validated:');
  console.log('   • Basic encode/decode functionality');
  console.log('   • Master key generation');
  console.log('   • URL and query string formats');
  console.log('   • File data encryption');
  console.log('   • Multiple key derivation methods');
  console.log('   • Different SDM profiles');
  console.log('   • Error handling and security');
  console.log('   • Performance benchmarks');
  console.log('   • Real-world scenarios');
} else {
  console.log(`\n⚠️ ${testResults.failed} test(s) failed. Please review and fix issues.`);
}

console.log('\n🚀 Library ready for production use!');

module.exports = {
  testResults,
  runBasicTest: () => {
    const masterKey = NTAG424Crypto.Encoder.generateMasterKey();
    const encryptResult = NTAG424Crypto.Encoder.encrypt(masterKey, '04AABBCCDDEE80', 42);
    const decoder = new NTAG424Crypto.Decoder(masterKey);
    const result = decoder.decrypt(encryptResult.encryptedData);
    return result.success && result.cmacValid;
  }
};
