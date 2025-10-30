/**
 * Test file for the Data Privacy Vault
 * Tests the anonymization functionality with various scenarios
 */

const request = require('http');

/**
 * Makes a POST request to test the anonymization endpoint
 * @param {string} message - The message to anonymize
 * @returns {Promise} - Promise that resolves with the response
 */
function testAnonymization(message) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ message });
    
    const options = {
      hostname: 'localhost',
      port: 3001,
      path: '/anonymize',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    const req = request.request(options, (res) => {
      let responseData = '';
      
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      
      res.on('end', () => {
        try {
          const response = JSON.parse(responseData);
          resolve({ statusCode: res.statusCode, data: response });
        } catch (error) {
          reject(error);
        }
      });
    });

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

/**
 * Run tests
 */
async function runTests() {
  console.log('🧪 Testing Data Privacy Vault...\n');

  try {
    // Test 1: Provided example
    console.log('Test 1: Provided example');
    const test1Message = "oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157";
    console.log('Input:', test1Message);
    
    const result1 = await testAnonymization(test1Message);
    console.log('Output:', result1.data.anonymizedMessage);
    console.log('Status:', result1.statusCode === 200 ? '✅ PASS' : '❌ FAIL');
    console.log('---\n');

    // Test 2: Multiple emails and phones
    console.log('Test 2: Multiple PII types');
    const test2Message = "Contact John Smith at john.smith@company.com or call 555-123-4567. Alternative: jane.doe@example.org, phone: +1 (555) 987-6543";
    console.log('Input:', test2Message);
    
    const result2 = await testAnonymization(test2Message);
    console.log('Output:', result2.data.anonymizedMessage);
    console.log('Status:', result2.statusCode === 200 ? '✅ PASS' : '❌ FAIL');
    console.log('---\n');

    // Test 3: Edge cases
    console.log('Test 3: Edge cases (no PII)');
    const test3Message = "This message contains no personal information.";
    console.log('Input:', test3Message);
    
    const result3 = await testAnonymization(test3Message);
    console.log('Output:', result3.data.anonymizedMessage);
    console.log('Status:', result3.statusCode === 200 ? '✅ PASS' : '❌ FAIL');
    console.log('---\n');

    // Test 4: Consistency check (same PII should generate same tokens)
    console.log('Test 4: Consistency check');
    const test4Message = "Email dborda@gmail.com again: dborda@gmail.com";
    console.log('Input:', test4Message);
    
    const result4 = await testAnonymization(test4Message);
    console.log('Output:', result4.data.anonymizedMessage);
    
    // Check if the same email generated the same token
    const tokens = result4.data.anonymizedMessage.match(/[a-f0-9]{8}/g);
    const isConsistent = tokens && tokens.length >= 2 && tokens[0] === tokens[1];
    console.log('Consistency:', isConsistent ? '✅ PASS' : '❌ FAIL');
    console.log('---\n');

    console.log('🎉 Tests completed!');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.log('\n💡 Make sure the server is running: npm start');
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  runTests();
}

module.exports = { testAnonymization, runTests };


