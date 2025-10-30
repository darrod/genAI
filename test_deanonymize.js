/**
 * Test file for the Deanonymization functionality
 * Tests the complete flow: anonymize -> deanonymize
 */

const request = require('http');

/**
 * Makes a POST request to test the anonymization and deanonymization endpoints
 */
function testEndpoint(message, endpoint, fieldName) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(message);
    
    const options = {
      hostname: 'localhost',
      port: 3001,
      path: `/${endpoint}`,
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
 * Run deanonymization tests
 */
async function runTests() {
  console.log('🧪 Testing Deanonymization...\n');

  try {
    const originalMessage = "oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157";
    
    // Step 1: Anonymize the message
    console.log('Step 1: Anonymizing message');
    console.log('Original:', originalMessage);
    
    const anonymizeResult = await testEndpoint(
      { message: originalMessage },
      'anonymize',
      'message'
    );
    
    console.log('Anonymized:', anonymizeResult.data.anonymizedMessage);
    console.log('Status:', anonymizeResult.statusCode === 200 ? '✅ PASS' : '❌ FAIL');
    console.log('---\n');
    
    const anonymizedMessage = anonymizeResult.data.anonymizedMessage;
    
    // Step 2: Deanonymize the message
    console.log('Step 2: Deanonymizing message');
    console.log('Anonymized:', anonymizedMessage);
    
    const deanonymizeResult = await testEndpoint(
      { anonymizedMessage: anonymizedMessage },
      'deanonymize',
      'anonymizedMessage'
    );
    
    console.log('Deanonymized:', deanonymizeResult.data.message);
    console.log('Status:', deanonymizeResult.statusCode === 200 ? '✅ PASS' : '❌ FAIL');
    console.log('---\n');
    
    // Step 3: Verify round-trip
    console.log('Step 3: Verifying round-trip');
    const roundTripSuccess = deanonymizeResult.data.message === originalMessage;
    console.log('Original === Deanonymized:', roundTripSuccess ? '✅ PASS' : '❌ FAIL');
    
    if (!roundTripSuccess) {
      console.log('Expected:', originalMessage);
      console.log('Got:', deanonymizeResult.data.message);
    }
    console.log('---\n');
    
    console.log('🎉 Deanonymization tests completed!');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.log('\n💡 Make sure the server is running: npm start');
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  runTests();
}

module.exports = { testEndpoint, runTests };

