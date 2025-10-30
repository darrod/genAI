# Creating a data privacy vault endpoint
_Exported on 10/29/2025 at 22:28:08 GMT-5 from Cursor (2.0.34)_

---

**User**

I am creating a Data Privacy Vault so that PII (Personally identifiable information) becomes anonymized using node.js.
I need to start with the first step: have an endpoint so that it receivesa single string with a message that contains PII like names, emails and phone numbers and returns it anonymized replacing the whole name, email and phone with an alphanumeric token.
Please act as an experienced node.js developer and tell me step by step how would you do it. Ask me for information whenever you need it and use good coding practices and comments in the functions.
An example of the request can be:
curl -X POST http://localhost:3001/anonymize -H "Content-Type: application/json" -d '{"message":"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"}'
The response to that request would be:
{
"anonymizedMessage": "oferta de trabajo para d7e8e0bf bd673df2 con email b09bde30 y teléfono dd195b6c"
}

---

**Cursor**

I'll help you create a Data Privacy Vault with Node.js. Let me break this down step by step and implement a solution that follows good coding practices.

```json
{
  "name": "data-privacy-vault",
  "version": "1.0.0",
  "description": "A Node.js service for anonymizing PII data using tokenization",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "node test.js"
  },
  "keywords": ["privacy", "anonymization", "pii", "data-protection"],
  "author": "",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "crypto": "^1.0.1",
    "cors": "^2.8.5"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization
 * Same PII value will always generate the same token
 */
const tokenCache = new Map();

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * @param {string} value - The original PII value to tokenize
 * @returns {string} - 8-character alphanumeric token
 */
function generateToken(value) {
  // Check if we already have a token for this value
  if (tokenCache.has(value)) {
    return tokenCache.get(value);
  }

  // Generate a consistent hash-based token
  const hash = crypto.createHash('sha256').update(value.toLowerCase()).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  
  // Store in cache for consistency
  tokenCache.set(value, token);
  
  return token;
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {string} - The anonymized message with tokens replacing PII
 */
function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  anonymized = anonymized.replace(PII_PATTERNS.email, (match) => {
    return generateToken(match);
  });

  // Step 2: Anonymize phone numbers
  anonymized = anonymized.replace(PII_PATTERNS.phone, (match) => {
    if (isValidPhone(match)) {
      return generateToken(match);
    }
    return match; // Return original if not a valid phone
  });

  // Step 3: Anonymize names (be careful with false positives)
  anonymized = anonymized.replace(PII_PATTERNS.name, (match) => {
    if (isValidName(match)) {
      return generateToken(match);
    }
    return match; // Return original if not likely a name
  });

  return anonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
});

module.exports = app;
```

```javascript
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
```

```markdown
# Data Privacy Vault

A Node.js service for anonymizing Personally Identifiable Information (PII) using tokenization. This service detects names, emails, and phone numbers in text and replaces them with consistent alphanumeric tokens.

## Features

- 🔒 **PII Detection**: Automatically detects names, emails, and phone numbers
- 🎯 **Consistent Tokenization**: Same PII value always generates the same token
- 🚀 **RESTful API**: Simple HTTP endpoint for integration
- ⚡ **Fast Processing**: In-memory tokenization for quick responses
- 🛡️ **Error Handling**: Comprehensive error handling and validation

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Start the Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will start on `http://localhost:3001`

### 3. Test the Service

```bash
npm test
```

## API Endpoints

### POST /anonymize

Anonymizes PII in a given message.

**Request:**
```bash
curl -X POST http://localhost:3001/anonymize \
  -H "Content-Type: application/json" \
  -d '{"message":"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"}'
```

**Response:**
```json
{
  "anonymizedMessage": "oferta de trabajo para d7e8e0bf bd673df2 con email b09bde30 y teléfono dd195b6c"
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Data Privacy Vault",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /stats

Returns anonymization statistics.

**Response:**
```json
{
  "totalTokensGenerated": 42,
  "service": "Data Privacy Vault"
}
```

## PII Detection

The service detects the following types of PII:

### 📧 Email Addresses
- Supports standard email formats
- Pattern: `user@domain.com`

### 📱 Phone Numbers
- Supports various formats: `3152319157`, `+57 315 231 9157`, `(315) 231-9157`
- Validates digit count (7-15 digits)

### 👤 Names
- Detects capitalized words (potential names)
- Basic validation to reduce false positives
- Pattern: `Firstname Lastname`

## Tokenization

- **Algorithm**: SHA-256 hash truncated to 8 characters
- **Consistency**: Same PII value always produces the same token
- **Format**: Lowercase alphanumeric (e.g., `a1b2c3d4`)

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Successful anonymization
- `400 Bad Request`: Invalid request format or missing message
- `500 Internal Server Error`: Server-side processing error

## Security Considerations

⚠️ **Important**: This is a basic implementation for demonstration purposes. For production use, consider:

- **Token Storage**: Implement secure token storage and retrieval
- **Advanced NLP**: Use more sophisticated name detection to reduce false positives
- **Logging**: Ensure no PII is logged in application logs
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **HTTPS**: Use HTTPS in production environments
- **Input Validation**: Add more comprehensive input validation

## Development

### Project Structure

```
data-privacy-vault/
├── server.js          # Main server file with anonymization logic
├── test.js            # Test suite
├── package.json       # Project configuration
└── README.md          # This file
```

### Adding New PII Types

To add detection for new PII types:

1. Add a new regex pattern to `PII_PATTERNS`
2. Add validation logic if needed
3. Update the `anonymizeMessage` function
4. Add tests for the new PII type

## License

MIT
```

---

**User**

me sale que npm no es reconocido como un nombre de cmdlet

---

**Cursor**

Ah, veo que npm no está instalado en tu sistema Windows. Necesitamos instalar Node.js primero, que incluye npm. Te explico paso a paso:

## Paso 1: Instalar Node.js

1. **Descarga Node.js:**
   - Ve a [https://nodejs.org](https://nodejs.org)
   - Descarga la versión **LTS** (Long Term Support) - recomendada para la mayoría de usuarios
   - Elige la versión para Windows (.msi)

2. **Instala Node.js:**
   - Ejecuta el archivo .msi descargado
   - Sigue el asistente de instalación (acepta los términos, usa la configuración por defecto)
   - **Importante**: Asegúrate de marcar la opción "Add to PATH" durante la instalación

3. **Verifica la instalación:**
   - Cierra y reabre PowerShell (importante para que se actualice el PATH)
   - Ejecuta estos comandos para verificar:

```bash
node --version
npm --version
```

Deberías ver algo como:
```
v18.17.0
9.6.7
```

## Paso 2: Una vez instalado Node.js

Cuando tengas Node.js instalado, podemos continuar con nuestro proyecto:

```bash
# Navegar al directorio del proyecto
cd "C:\Users\User\Documents\Cursor\Taller2-3"

# Instalar dependencias
npm install

# Ejecutar el servidor
npm start
```

## Alternativa rápida: Usar Chocolatey (si lo tienes instalado)

Si tienes Chocolatey instalado, puedes instalar Node.js rápidamente:

```powershell
choco install nodejs
```

---

**Después de instalar Node.js, confirma que funciona ejecutando `node --version` y `npm --version`, y entonces podremos continuar con el proyecto de Data Privacy Vault.**

¿Ya tienes Node.js instalado o necesitas ayuda con algún paso específico de la instalación?

```shellscript
node --version
npm --version
```

```plaintext
v18.17.0
9.6.7
```

```shellscript
# Navegar al directorio del proyecto
cd "C:\Users\User\Documents\Cursor\Taller2-3"

# Instalar dependencias
npm install

# Ejecutar el servidor
npm start
```

```powershell
choco install nodejs
```

---

**User**

ya, nodejs ya esta instslado y la variable PATH ya tiene el valor donde esta instslado: C:\Program Files\nodejs\: 

---

**Cursor**

Perfecto! Ya que tienes Node.js instalado y la variable PATH configurada, ahora podemos continuar con el proyecto. Vamos a instalar las dependencias y ejecutar el servidor:

Veo que npm aún no es reconocido en tu PowerShell actual. Esto puede suceder porque la sesión de PowerShell necesita ser reiniciada para leer las nuevas variables de entorno. Vamos a solucionarlo:

## Opciones para resolver el problema:

### Opción 1: Reiniciar PowerShell (Recomendado)
1. **Cierra completamente** la ventana de PowerShell actual
2. **Abre una nueva ventana** de PowerShell
3. Navega de nuevo al directorio del proyecto:

```powershell
cd "C:\Users\User\Documents\Cursor\Taller2-3"
```

### Opción 2: Refrescar las variables de entorno en la sesión actual

```powershell
cd "C:\Users\User\Documents\Cursor\Taller2-3"
```

Ahora vamos a verificar si npm está disponible y luego instalar las dependencias:

---

**User**

el comando npm --version no funciona.  El comando que si me funciona es npm.cmd --version,. como lo resuelvo?

---

**Cursor**

¡Perfecto! Ese es un problema común en Windows PowerShell. El comando `npm` es en realidad un archivo `.cmd` y PowerShell a veces necesita la extensión explícita. Te muestro varias formas de resolverlo:

## Solución 1: Crear un alias en PowerShell (Recomendado)

Ahora vamos a verificar que npm funciona y luego instalaremos las dependencias:

---

**User**

I got this error:
Unhandled error: SyntaxError: Unexpected token ''', "'{message:"... is not valid JSON
When I try to test the endpoint using this message:
curl -X POST http://localhost:3001/anonymize -H "Content-Type: application/json" -d '{"message":"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"}'
help me to fix it

---

**Cursor**

I see the issue! This is a common problem with Windows PowerShell and JSON formatting. The single quotes around the JSON data are causing parsing issues. Let me help you fix this.

## The Problem
Windows PowerShell handles quotes differently than Unix shells, and the JSON parsing is failing because of the quote formatting.

## Solutions:

### Solution 1: Use double quotes and escape inner quotes (Windows PowerShell)

---

**User**

Thanks. Now, let's implement the deanonymize endpoint where the calling should be like this:
curl -X POST http://localhost:3001/deanonymize -H "Content-Type: application/json" -d '{"anonymizedMessage":"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y telefono PHONE_40e83067b9cb"}'
and should return the original message:
{"message":"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"}

---

**Cursor**

Perfecto! Necesitamos implementar un endpoint de deanonimización. Sin embargo, hay algo importante que debemos considerar: para poder "deanonymizar" un mensaje, necesitamos almacenar el mapeo entre tokens y valores originales.

Déjame explicar los cambios necesarios:


Ahora voy a actualizar el código para implementar la funcionalidad de deanonimización. Los cambios principales serán:
1. Almacenar un mapeo reverso (token → valor original)
2. Agregar prefijos de tipo a los tokens (NAME_, EMAIL_, PHONE_)
3. Crear el endpoint de deanonimización


```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization
 * Same PII value will always generate the same token
 * Map: original_value -> token
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization
 * Map: token -> { value: original_value, type: PII_type }
 */
const reverseTokenCache = new Map();

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * @param {string} value - The original PII value to tokenize
 * @returns {string} - 8-character alphanumeric token
 */
function generateToken(value) {
  // Check if we already have a token for this value
  if (tokenCache.has(value)) {
    return tokenCache.get(value);
  }

  // Generate a consistent hash-based token
  const hash = crypto.createHash('sha256').update(value.toLowerCase()).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  
  // Store in cache for consistency
  tokenCache.set(value, token);
  
  return token;
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {string} - The anonymized message with tokens replacing PII
 */
function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  anonymized = anonymized.replace(PII_PATTERNS.email, (match) => {
    return generateToken(match);
  });

  // Step 2: Anonymize phone numbers
  anonymized = anonymized.replace(PII_PATTERNS.phone, (match) => {
    if (isValidPhone(match)) {
      return generateToken(match);
    }
    return match; // Return original if not a valid phone
  });

  // Step 3: Anonymize names (be careful with false positives)
  anonymized = anonymized.replace(PII_PATTERNS.name, (match) => {
    if (isValidName(match)) {
      return generateToken(match);
    }
    return match; // Return original if not likely a name
  });

  return anonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
});

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization
 * Same PII value will always generate the same token
 * Map: original_value -> token
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization
 * Map: token -> { value: original_value, type: PII_type }
 */
const reverseTokenCache = new Map();

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {string} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
function generateToken(value, type) {
  // Check if we already have a token for this value
  if (tokenCache.has(value)) {
    const existingToken = tokenCache.get(value);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Generate a consistent hash-based token
  const hash = crypto.createHash('sha256').update(value.toLowerCase()).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in both caches for consistency and deanonymization
  tokenCache.set(value, token);
  reverseTokenCache.set(token, { value: value, type: type });
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {string} - The anonymized message with tokens replacing PII
 */
function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  anonymized = anonymized.replace(PII_PATTERNS.email, (match) => {
    return generateToken(match);
  });

  // Step 2: Anonymize phone numbers
  anonymized = anonymized.replace(PII_PATTERNS.phone, (match) => {
    if (isValidPhone(match)) {
      return generateToken(match);
    }
    return match; // Return original if not a valid phone
  });

  // Step 3: Anonymize names (be careful with false positives)
  anonymized = anonymized.replace(PII_PATTERNS.name, (match) => {
    if (isValidName(match)) {
      return generateToken(match);
    }
    return match; // Return original if not likely a name
  });

  return anonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
});

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization
 * Same PII value will always generate the same token
 * Map: original_value -> token
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization
 * Map: token -> { value: original_value, type: PII_type }
 */
const reverseTokenCache = new Map();

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {string} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
function generateToken(value, type) {
  // Check if we already have a token for this value
  if (tokenCache.has(value)) {
    const existingToken = tokenCache.get(value);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Generate a consistent hash-based token
  const hash = crypto.createHash('sha256').update(value.toLowerCase()).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in both caches for consistency and deanonymization
  tokenCache.set(value, token);
  reverseTokenCache.set(token, { value: value, type: type });
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {string} - The anonymized message with tokens replacing PII
 */
function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  anonymized = anonymized.replace(PII_PATTERNS.email, (match) => {
    return generateToken(match, 'EMAIL');
  });

  // Step 2: Anonymize phone numbers
  anonymized = anonymized.replace(PII_PATTERNS.phone, (match) => {
    if (isValidPhone(match)) {
      return generateToken(match, 'PHONE');
    }
    return match; // Return original if not a valid phone
  });

  // Step 3: Anonymize names (be careful with false positives)
  anonymized = anonymized.replace(PII_PATTERNS.name, (match) => {
    if (isValidName(match)) {
      return generateToken(match, 'NAME');
    }
    return match; // Return original if not likely a name
  });

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {string} - The deanonymized message with original PII values
 */
function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  
  // Replace all tokens with their original values
  deanonymized = deanonymized.replace(tokenPattern, (match) => {
    const token = extractToken(match);
    
    if (!token) {
      return match; // Return original if token extraction fails
    }
    
    const originalData = reverseTokenCache.get(token);
    
    if (originalData) {
      return originalData.value;
    }
    
    // Token not found in cache - return original token
    console.warn(`Warning: Token ${match} not found in deanonymization cache`);
    return match;
  });
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
});

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization
 * Same PII value will always generate the same token
 * Map: original_value -> token
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization
 * Map: token -> { value: original_value, type: PII_type }
 */
const reverseTokenCache = new Map();

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {string} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
function generateToken(value, type) {
  // Check if we already have a token for this value
  if (tokenCache.has(value)) {
    const existingToken = tokenCache.get(value);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Generate a consistent hash-based token
  const hash = crypto.createHash('sha256').update(value.toLowerCase()).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in both caches for consistency and deanonymization
  tokenCache.set(value, token);
  reverseTokenCache.set(token, { value: value, type: type });
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {string} - The anonymized message with tokens replacing PII
 */
function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  anonymized = anonymized.replace(PII_PATTERNS.email, (match) => {
    return generateToken(match, 'EMAIL');
  });

  // Step 2: Anonymize phone numbers
  anonymized = anonymized.replace(PII_PATTERNS.phone, (match) => {
    if (isValidPhone(match)) {
      return generateToken(match, 'PHONE');
    }
    return match; // Return original if not a valid phone
  });

  // Step 3: Anonymize names (be careful with false positives)
  anonymized = anonymized.replace(PII_PATTERNS.name, (match) => {
    if (isValidName(match)) {
      return generateToken(match, 'NAME');
    }
    return match; // Return original if not likely a name
  });

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {string} - The deanonymized message with original PII values
 */
function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  
  // Replace all tokens with their original values
  deanonymized = deanonymized.replace(tokenPattern, (match) => {
    const token = extractToken(match);
    
    if (!token) {
      return match; // Return original if token extraction fails
    }
    
    const originalData = reverseTokenCache.get(token);
    
    if (originalData) {
      return originalData.value;
    }
    
    // Token not found in cache - return original token
    console.warn(`Warning: Token ${match} not found in deanonymization cache`);
    return match;
  });
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message
    const message = deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    totalTokensAvailable: reverseTokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
});

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization
 * Same PII value will always generate the same token
 * Map: original_value -> token
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization
 * Map: token -> { value: original_value, type: PII_type }
 */
const reverseTokenCache = new Map();

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {string} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
function generateToken(value, type) {
  // Check if we already have a token for this value
  if (tokenCache.has(value)) {
    const existingToken = tokenCache.get(value);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Generate a consistent hash-based token
  const hash = crypto.createHash('sha256').update(value.toLowerCase()).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in both caches for consistency and deanonymization
  tokenCache.set(value, token);
  reverseTokenCache.set(token, { value: value, type: type });
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {string} - The anonymized message with tokens replacing PII
 */
function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  anonymized = anonymized.replace(PII_PATTERNS.email, (match) => {
    return generateToken(match, 'EMAIL');
  });

  // Step 2: Anonymize phone numbers
  anonymized = anonymized.replace(PII_PATTERNS.phone, (match) => {
    if (isValidPhone(match)) {
      return generateToken(match, 'PHONE');
    }
    return match; // Return original if not a valid phone
  });

  // Step 3: Anonymize names (be careful with false positives)
  anonymized = anonymized.replace(PII_PATTERNS.name, (match) => {
    if (isValidName(match)) {
      return generateToken(match, 'NAME');
    }
    return match; // Return original if not likely a name
  });

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {string} - The deanonymized message with original PII values
 */
function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  
  // Replace all tokens with their original values
  deanonymized = deanonymized.replace(tokenPattern, (match) => {
    const token = extractToken(match);
    
    if (!token) {
      return match; // Return original if token extraction fails
    }
    
    const originalData = reverseTokenCache.get(token);
    
    if (originalData) {
      return originalData.value;
    }
    
    // Token not found in cache - return original token
    console.warn(`Warning: Token ${match} not found in deanonymization cache`);
    return match;
  });
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message
    const message = deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    totalTokensAvailable: reverseTokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
  console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
});

module.exports = app;


```

Actualizando el README con el nuevo endpoint.


```markdown
# Data Privacy Vault

A Node.js service for anonymizing Personally Identifiable Information (PII) using tokenization. This service detects names, emails, and phone numbers in text and replaces them with consistent alphanumeric tokens.

## Features

- 🔒 **PII Detection**: Automatically detects names, emails, and phone numbers
- 🎯 **Consistent Tokenization**: Same PII value always generates the same token
- 🚀 **RESTful API**: Simple HTTP endpoint for integration
- ⚡ **Fast Processing**: In-memory tokenization for quick responses
- 🛡️ **Error Handling**: Comprehensive error handling and validation

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Start the Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will start on `http://localhost:3001`

### 3. Test the Service

```bash
npm test
```

## API Endpoints

### POST /anonymize

Anonymizes PII in a given message.

**Request:**
```bash
curl -X POST http://localhost:3001/anonymize \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"
```

**Response:**
```json
{
  "anonymizedMessage": "oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb"
}
```

### POST /deanonymize

Deanonymizes a message by converting tokens back to original PII values.

**Request:**
```bash
curl -X POST http://localhost:3001/deanonymize \
  -H "Content-Type: application/json" \
  -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

**Response:**
```json
{
  "message": "oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Data Privacy Vault",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /stats

Returns anonymization statistics.

**Response:**
```json
{
  "totalTokensGenerated": 42,
  "service": "Data Privacy Vault"
}
```

## PII Detection

The service detects the following types of PII:

### 📧 Email Addresses
- Supports standard email formats
- Pattern: `user@domain.com`

### 📱 Phone Numbers
- Supports various formats: `3152319157`, `+57 315 231 9157`, `(315) 231-9157`
- Validates digit count (7-15 digits)

### 👤 Names
- Detects capitalized words (potential names)
- Basic validation to reduce false positives
- Pattern: `Firstname Lastname`

## Tokenization

- **Algorithm**: SHA-256 hash truncated to 8 characters
- **Consistency**: Same PII value always produces the same token
- **Format**: Lowercase alphanumeric (e.g., `a1b2c3d4`)

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Successful anonymization
- `400 Bad Request`: Invalid request format or missing message
- `500 Internal Server Error`: Server-side processing error

## Security Considerations

⚠️ **Important**: This is a basic implementation for demonstration purposes. For production use, consider:

- **Token Storage**: Implement secure token storage and retrieval
- **Advanced NLP**: Use more sophisticated name detection to reduce false positives
- **Logging**: Ensure no PII is logged in application logs
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **HTTPS**: Use HTTPS in production environments
- **Input Validation**: Add more comprehensive input validation

## Development

### Project Structure

```
data-privacy-vault/
├── server.js          # Main server file with anonymization logic
├── test.js            # Test suite
├── package.json       # Project configuration
└── README.md          # This file
```

### Adding New PII Types

To add detection for new PII types:

1. Add a new regex pattern to `PII_PATTERNS`
2. Add validation logic if needed
3. Update the `anonymizeMessage` function
4. Add tests for the new PII type

## License

MIT

```

```markdown
# Data Privacy Vault

A Node.js service for anonymizing Personally Identifiable Information (PII) using tokenization. This service detects names, emails, and phone numbers in text and replaces them with consistent alphanumeric tokens.

## Features

- 🔒 **PII Detection**: Automatically detects names, emails, and phone numbers
- 🎯 **Consistent Tokenization**: Same PII value always generates the same token
- 🚀 **RESTful API**: Simple HTTP endpoint for integration
- ⚡ **Fast Processing**: In-memory tokenization for quick responses
- 🛡️ **Error Handling**: Comprehensive error handling and validation

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Start the Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will start on `http://localhost:3001`

### 3. Test the Service

```bash
npm test
```

## API Endpoints

### POST /anonymize

Anonymizes PII in a given message.

**Request:**
```bash
curl -X POST http://localhost:3001/anonymize \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"
```

**Response:**
```json
{
  "anonymizedMessage": "oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb"
}
```

### POST /deanonymize

Deanonymizes a message by converting tokens back to original PII values.

**Request:**
```bash
curl -X POST http://localhost:3001/deanonymize \
  -H "Content-Type: application/json" \
  -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

**Response:**
```json
{
  "message": "oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Data Privacy Vault",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /stats

Returns anonymization statistics.

**Response:**
```json
{
  "totalTokensGenerated": 42,
  "service": "Data Privacy Vault"
}
```

## PII Detection

The service detects the following types of PII:

### 📧 Email Addresses
- Supports standard email formats
- Pattern: `user@domain.com`

### 📱 Phone Numbers
- Supports various formats: `3152319157`, `+57 315 231 9157`, `(315) 231-9157`
- Validates digit count (7-15 digits)

### 👤 Names
- Detects capitalized words (potential names)
- Basic validation to reduce false positives
- Pattern: `Firstname Lastname`

## Tokenization

- **Algorithm**: SHA-256 hash truncated to 8 characters
- **Consistency**: Same PII value always produces the same token
- **Format**: Type prefix + lowercase alphanumeric (e.g., `EMAIL_a1b2c3d4`)
- **Reversibility**: Tokens can be reversed to original values using the `/deanonymize` endpoint
- **PII Types**: 
  - `NAME_` - For names
  - `EMAIL_` - For email addresses
  - `PHONE_` - For phone numbers

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Successful anonymization
- `400 Bad Request`: Invalid request format or missing message
- `500 Internal Server Error`: Server-side processing error

## Security Considerations

⚠️ **Important**: This is a basic implementation for demonstration purposes. For production use, consider:

- **Token Storage**: Implement secure token storage and retrieval
- **Advanced NLP**: Use more sophisticated name detection to reduce false positives
- **Logging**: Ensure no PII is logged in application logs
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **HTTPS**: Use HTTPS in production environments
- **Input Validation**: Add more comprehensive input validation

## Development

### Project Structure

```
data-privacy-vault/
├── server.js          # Main server file with anonymization logic
├── test.js            # Test suite
├── package.json       # Project configuration
└── README.md          # This file
```

### Adding New PII Types

To add detection for new PII types:

1. Add a new regex pattern to `PII_PATTERNS`
2. Add validation logic if needed
3. Update the `anonymizeMessage` function
4. Add tests for the new PII type

## License

MIT

```

Preparando un archivo de prueba para verificar el flujo completo de anonimización y desanonimización:


```javascript
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
```

## Resumen de cambios implementados

### 1. **Sistema de almacenamiento bidireccional**
- `tokenCache`: almacena mapeo `valor_original → token`
- `reverseTokenCache`: almacena mapeo `token → { valor, tipo }` para desanonimización

### 2. **Formato de token con prefijo de tipo**
Tokens con formato: `TIPO_token8chars`
- `NAME_e1be92e2` - Para nombres
- `EMAIL_8004719c` - Para emails
- `PHONE_40e83067` - Para teléfonos

### 3. **Funciones auxiliares**
- `generateToken(value, type)`: genera tokens con tipo
- `extractToken(formattedToken)`: extrae el token del prefijo
- `getTokenType(formattedToken)`: obtiene el tipo de PII

### 4. **Función de desanonimización**
`deanonymizeMessage(anonymizedMessage)`:
- Detecta tokens con el patrón `TYPE_token8chars`
- Busca valores originales en `reverseTokenCache`
- Reemplaza tokens por valores originales

### 5. **Nuevo endpoint POST /deanonymize**
- Entrada: `{ "anonymizedMessage": "..." }`
- Salida: `{ "message": "..." }`
- Manejo de errores
- Validaciones de entrada

## Cómo probar

Si el servidor ya está ejecutándose, reinícialo para cargar los cambios:

```bash
# Detener el servidor actual (Ctrl+C)
# Luego iniciarlo de nuevo
npm start
```

Luego, prueba con:

```bash
# Anonymize
curl -X POST http://localhost:3001/anonymize -H "Content-Type: application/json" -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"

# Deanonymize (usa los tokens que obtengas del paso anterior)
curl -X POST http://localhost:3001/deanonymize -H "Content-Type: application/json" -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

### Prueba alternativa
Para verificar el flujo completo:

```bash
node test_deanonymize.js
```

¿Quieres que ejecute estas pruebas ahora o prefieres hacerlo manualmente?

```shellscript
# Detener el servidor actual (Ctrl+C)
# Luego iniciarlo de nuevo
npm start
```

```shellscript
# Anonymize
curl -X POST http://localhost:3001/anonymize -H "Content-Type: application/json" -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"

# Deanonymize (usa los tokens que obtengas del paso anterior)
curl -X POST http://localhost:3001/deanonymize -H "Content-Type: application/json" -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

```shellscript
node test_deanonymize.js
```

---

**User**

Thanks. Now, I want to implement a way to store the pairs (private information, token) in MongoDB Atlas to both anonymize and deanonymize services.

---

**Cursor**

Perfecto! Ahora vamos a integrar MongoDB Atlas para almacenar de forma persistente los pares (información privada, token). Esto hará que nuestro servicio sea más robusto y los datos perduren incluso si el servidor se reinicia.


```json
{
  "name": "data-privacy-vault",
  "version": "1.0.0",
  "description": "A Node.js service for anonymizing PII data using tokenization",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "node test.js"
  },
  "keywords": ["privacy", "anonymization", "pii", "data-protection"],
  "author": "",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "crypto": "^1.0.1",
    "cors": "^2.8.5",
    "mongoose": "^8.0.3",
    "dotenv": "^16.3.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}


```

```plaintext
# MongoDB Atlas Connection String
# Replace with your actual MongoDB Atlas connection string
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/data-privacy-vault?retryWrites=true&w=majority

# Server Configuration
PORT=3001

# Node Environment
NODE_ENV=development
```

```javascript
const mongoose = require('mongoose');

/**
 * Schema for storing PII token mappings
 * This model stores the relationship between original PII values and their tokens
 */
const tokenSchema = new mongoose.Schema({
  // The original PII value (name, email, or phone)
  originalValue: {
    type: String,
    required: true,
    index: true, // Index for faster lookups
    unique: true // Ensure one PII value maps to one token
  },
  
  // The generated token (8-character hash)
  token: {
    type: String,
    required: true,
    index: true, // Index for faster reverse lookups
    unique: true // Ensure token uniqueness
  },
  
  // Type of PII: 'NAME', 'EMAIL', or 'PHONE'
  type: {
    type: String,
    required: true,
    enum: ['NAME', 'EMAIL', 'PHONE'],
    index: true
  },
  
  // Timestamp when the token was created
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  // Last time this token was used
  lastUsedAt: {
    type: Date,
    default: Date.now
  },
  
  // Usage count - track how many times this token has been used
  usageCount: {
    type: Number,
    default: 0
  }
}, {
  // Options
  timestamps: true // Automatically add createdAt and updatedAt fields
});

// Compound index for efficient querying
tokenSchema.index({ originalValue: 1, type: 1 });

// Compound index for deanonymization lookups
tokenSchema.index({ token: 1, type: 1 });

/**
 * Static method to find token by original value
 * @param {string} originalValue - The original PII value
 * @returns {Promise} - Token document or null
 */
tokenSchema.statics.findByOriginalValue = function(originalValue) {
  return this.findOne({ originalValue: originalValue.toLowerCase() });
};

/**
 * Static method to find original value by token
 * @param {string} token - The generated token
 * @returns {Promise} - Token document or null
 */
tokenSchema.statics.findByToken = function(token) {
  return this.findOne({ token: token });
};

/**
 * Instance method to update usage statistics
 */
tokenSchema.methods.incrementUsage = function() {
  this.usageCount += 1;
  this.lastUsedAt = new Date();
  return this.save();
};

// Create the model
const Token = mongoose.model('Token', tokenSchema);

module.exports = Token;
```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization
 * Same PII value will always generate the same token
 * Map: original_value -> token
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization
 * Map: token -> { value: original_value, type: PII_type }
 */
const reverseTokenCache = new Map();

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {string} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
function generateToken(value, type) {
  // Check if we already have a token for this value
  if (tokenCache.has(value)) {
    const existingToken = tokenCache.get(value);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Generate a consistent hash-based token
  const hash = crypto.createHash('sha256').update(value.toLowerCase()).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in both caches for consistency and deanonymization
  tokenCache.set(value, token);
  reverseTokenCache.set(token, { value: value, type: type });
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {string} - The anonymized message with tokens replacing PII
 */
function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  anonymized = anonymized.replace(PII_PATTERNS.email, (match) => {
    return generateToken(match, 'EMAIL');
  });

  // Step 2: Anonymize phone numbers
  anonymized = anonymized.replace(PII_PATTERNS.phone, (match) => {
    if (isValidPhone(match)) {
      return generateToken(match, 'PHONE');
    }
    return match; // Return original if not a valid phone
  });

  // Step 3: Anonymize names (be careful with false positives)
  anonymized = anonymized.replace(PII_PATTERNS.name, (match) => {
    if (isValidName(match)) {
      return generateToken(match, 'NAME');
    }
    return match; // Return original if not likely a name
  });

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {string} - The deanonymized message with original PII values
 */
function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  
  // Replace all tokens with their original values
  deanonymized = deanonymized.replace(tokenPattern, (match) => {
    const token = extractToken(match);
    
    if (!token) {
      return match; // Return original if token extraction fails
    }
    
    const originalData = reverseTokenCache.get(token);
    
    if (originalData) {
      return originalData.value;
    }
    
    // Token not found in cache - return original token
    console.warn(`Warning: Token ${match} not found in deanonymization cache`);
    return match;
  });
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message
    const message = deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    totalTokensAvailable: reverseTokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
  console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
});

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {string} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
function generateToken(value, type) {
  // Check if we already have a token for this value
  if (tokenCache.has(value)) {
    const existingToken = tokenCache.get(value);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Generate a consistent hash-based token
  const hash = crypto.createHash('sha256').update(value.toLowerCase()).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in both caches for consistency and deanonymization
  tokenCache.set(value, token);
  reverseTokenCache.set(token, { value: value, type: type });
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {string} - The anonymized message with tokens replacing PII
 */
function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  anonymized = anonymized.replace(PII_PATTERNS.email, (match) => {
    return generateToken(match, 'EMAIL');
  });

  // Step 2: Anonymize phone numbers
  anonymized = anonymized.replace(PII_PATTERNS.phone, (match) => {
    if (isValidPhone(match)) {
      return generateToken(match, 'PHONE');
    }
    return match; // Return original if not a valid phone
  });

  // Step 3: Anonymize names (be careful with false positives)
  anonymized = anonymized.replace(PII_PATTERNS.name, (match) => {
    if (isValidName(match)) {
      return generateToken(match, 'NAME');
    }
    return match; // Return original if not likely a name
  });

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {string} - The deanonymized message with original PII values
 */
function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  
  // Replace all tokens with their original values
  deanonymized = deanonymized.replace(tokenPattern, (match) => {
    const token = extractToken(match);
    
    if (!token) {
      return match; // Return original if token extraction fails
    }
    
    const originalData = reverseTokenCache.get(token);
    
    if (originalData) {
      return originalData.value;
    }
    
    // Token not found in cache - return original token
    console.warn(`Warning: Token ${match} not found in deanonymization cache`);
    return match;
  });
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message
    const message = deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    totalTokensAvailable: reverseTokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
  console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
});

module.exports = app;


```

Ahora actualizando la función `generateToken` para guardar en MongoDB:


```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  try {
    const existingDoc = await Token.findByOriginalValue(normalizedValue);
    
    if (existingDoc) {
      // Token exists in database - load into cache
      const token = existingDoc.token;
      const docType = existingDoc.type;
      
      // Populate caches
      tokenCache.set(normalizedValue, token);
      reverseTokenCache.set(token, { value: normalizedValue, type: docType });
      
      return `${docType}_${token}`;
    }
  } catch (error) {
    console.error('Error checking MongoDB for existing token:', error.message);
    // Continue to generate new token
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence
  try {
    const newToken = new Token({
      originalValue: normalizedValue,
      token: token,
      type: type
    });
    
    await newToken.save();
    console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
    
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key error - token already exists (race condition)
      console.warn(`Token ${token} already exists in database`);
    } else {
      console.error('Error saving token to MongoDB:', error.message);
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {string} - The anonymized message with tokens replacing PII
 */
function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  anonymized = anonymized.replace(PII_PATTERNS.email, (match) => {
    return generateToken(match, 'EMAIL');
  });

  // Step 2: Anonymize phone numbers
  anonymized = anonymized.replace(PII_PATTERNS.phone, (match) => {
    if (isValidPhone(match)) {
      return generateToken(match, 'PHONE');
    }
    return match; // Return original if not a valid phone
  });

  // Step 3: Anonymize names (be careful with false positives)
  anonymized = anonymized.replace(PII_PATTERNS.name, (match) => {
    if (isValidName(match)) {
      return generateToken(match, 'NAME');
    }
    return match; // Return original if not likely a name
  });

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {string} - The deanonymized message with original PII values
 */
function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  
  // Replace all tokens with their original values
  deanonymized = deanonymized.replace(tokenPattern, (match) => {
    const token = extractToken(match);
    
    if (!token) {
      return match; // Return original if token extraction fails
    }
    
    const originalData = reverseTokenCache.get(token);
    
    if (originalData) {
      return originalData.value;
    }
    
    // Token not found in cache - return original token
    console.warn(`Warning: Token ${match} not found in deanonymization cache`);
    return match;
  });
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message
    const message = deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    totalTokensAvailable: reverseTokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
  console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
});

module.exports = app;


```

Actualizando las funciones que usan `generateToken` para manejar el async/await:


```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  try {
    const existingDoc = await Token.findByOriginalValue(normalizedValue);
    
    if (existingDoc) {
      // Token exists in database - load into cache
      const token = existingDoc.token;
      const docType = existingDoc.type;
      
      // Populate caches
      tokenCache.set(normalizedValue, token);
      reverseTokenCache.set(token, { value: normalizedValue, type: docType });
      
      return `${docType}_${token}`;
    }
  } catch (error) {
    console.error('Error checking MongoDB for existing token:', error.message);
    // Continue to generate new token
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence
  try {
    const newToken = new Token({
      originalValue: normalizedValue,
      token: token,
      type: type
    });
    
    await newToken.save();
    console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
    
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key error - token already exists (race condition)
      console.warn(`Token ${token} already exists in database`);
    } else {
      console.error('Error saving token to MongoDB:', error.message);
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {string} - The deanonymized message with original PII values
 */
function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  
  // Replace all tokens with their original values
  deanonymized = deanonymized.replace(tokenPattern, (match) => {
    const token = extractToken(match);
    
    if (!token) {
      return match; // Return original if token extraction fails
    }
    
    const originalData = reverseTokenCache.get(token);
    
    if (originalData) {
      return originalData.value;
    }
    
    // Token not found in cache - return original token
    console.warn(`Warning: Token ${match} not found in deanonymization cache`);
    return match;
  });
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message
    const message = deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    totalTokensAvailable: reverseTokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
  console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
});

module.exports = app;


```

Actualizando la función de deanonymize para consultar MongoDB:


```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  try {
    const existingDoc = await Token.findByOriginalValue(normalizedValue);
    
    if (existingDoc) {
      // Token exists in database - load into cache
      const token = existingDoc.token;
      const docType = existingDoc.type;
      
      // Populate caches
      tokenCache.set(normalizedValue, token);
      reverseTokenCache.set(token, { value: normalizedValue, type: docType });
      
      return `${docType}_${token}`;
    }
  } catch (error) {
    console.error('Error checking MongoDB for existing token:', error.message);
    // Continue to generate new token
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence
  try {
    const newToken = new Token({
      originalValue: normalizedValue,
      token: token,
      type: type
    });
    
    await newToken.save();
    console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
    
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key error - token already exists (race condition)
      console.warn(`Token ${token} already exists in database`);
    } else {
      console.error('Error saving token to MongoDB:', error.message);
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB
    if (!originalData) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message
    const anonymizedMessage = anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message
    const message = deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    totalTokensAvailable: reverseTokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
  console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
});

module.exports = app;


```

Actualizando endpoints para manejar async/await:


```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  try {
    const existingDoc = await Token.findByOriginalValue(normalizedValue);
    
    if (existingDoc) {
      // Token exists in database - load into cache
      const token = existingDoc.token;
      const docType = existingDoc.type;
      
      // Populate caches
      tokenCache.set(normalizedValue, token);
      reverseTokenCache.set(token, { value: normalizedValue, type: docType });
      
      return `${docType}_${token}`;
    }
  } catch (error) {
    console.error('Error checking MongoDB for existing token:', error.message);
    // Continue to generate new token
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence
  try {
    const newToken = new Token({
      originalValue: normalizedValue,
      token: token,
      type: type
    });
    
    await newToken.save();
    console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
    
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key error - token already exists (race condition)
      console.warn(`Token ${token} already exists in database`);
    } else {
      console.error('Error saving token to MongoDB:', error.message);
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB
    if (!originalData) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message
    const message = deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    totalTokensAvailable: reverseTokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
  console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
});

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  try {
    const existingDoc = await Token.findByOriginalValue(normalizedValue);
    
    if (existingDoc) {
      // Token exists in database - load into cache
      const token = existingDoc.token;
      const docType = existingDoc.type;
      
      // Populate caches
      tokenCache.set(normalizedValue, token);
      reverseTokenCache.set(token, { value: normalizedValue, type: docType });
      
      return `${docType}_${token}`;
    }
  } catch (error) {
    console.error('Error checking MongoDB for existing token:', error.message);
    // Continue to generate new token
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence
  try {
    const newToken = new Token({
      originalValue: normalizedValue,
      token: token,
      type: type
    });
    
    await newToken.save();
    console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
    
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key error - token already exists (race condition)
      console.warn(`Token ${token} already exists in database`);
    } else {
      console.error('Error saving token to MongoDB:', error.message);
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB
    if (!originalData) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', (req, res) => {
  res.json({
    totalTokensGenerated: tokenCache.size,
    totalTokensAvailable: reverseTokenCache.size,
    service: 'Data Privacy Vault'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
  console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
});

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  try {
    const existingDoc = await Token.findByOriginalValue(normalizedValue);
    
    if (existingDoc) {
      // Token exists in database - load into cache
      const token = existingDoc.token;
      const docType = existingDoc.type;
      
      // Populate caches
      tokenCache.set(normalizedValue, token);
      reverseTokenCache.set(token, { value: normalizedValue, type: docType });
      
      return `${docType}_${token}`;
    }
  } catch (error) {
    console.error('Error checking MongoDB for existing token:', error.message);
    // Continue to generate new token
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence
  try {
    const newToken = new Token({
      originalValue: normalizedValue,
      token: token,
      type: type
    });
    
    await newToken.save();
    console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
    
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key error - token already exists (race condition)
      console.warn(`Token ${token} already exists in database`);
    } else {
      console.error('Error saving token to MongoDB:', error.message);
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB
    if (!originalData) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
  console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
});

module.exports = app;


```

Actualizando la sección donde se inicia el servidor para conectar la base de datos:


```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  try {
    const existingDoc = await Token.findByOriginalValue(normalizedValue);
    
    if (existingDoc) {
      // Token exists in database - load into cache
      const token = existingDoc.token;
      const docType = existingDoc.type;
      
      // Populate caches
      tokenCache.set(normalizedValue, token);
      reverseTokenCache.set(token, { value: normalizedValue, type: docType });
      
      return `${docType}_${token}`;
    }
  } catch (error) {
    console.error('Error checking MongoDB for existing token:', error.message);
    // Continue to generate new token
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence
  try {
    const newToken = new Token({
      originalValue: normalizedValue,
      token: token,
      type: type
    });
    
    await newToken.save();
    console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
    
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key error - token already exists (race condition)
      console.warn(`Token ${token} already exists in database`);
    } else {
      console.error('Error saving token to MongoDB:', error.message);
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB
    if (!originalData) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server and connect to database
(async () => {
  // Connect to MongoDB Atlas
  await connectDatabase();
  
  // Start the Express server
  app.listen(PORT, () => {
    console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
    console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
    console.log(`📈 Stats endpoint: GET http://localhost:${PORT}/stats`);
  });
})();

module.exports = app;


```

Actualizando el README con las instrucciones de MongoDB.


```markdown
# Data Privacy Vault

A Node.js service for anonymizing Personally Identifiable Information (PII) using tokenization. This service detects names, emails, and phone numbers in text and replaces them with consistent alphanumeric tokens.

## Features

- 🔒 **PII Detection**: Automatically detects names, emails, and phone numbers
- 🎯 **Consistent Tokenization**: Same PII value always generates the same token
- 🚀 **RESTful API**: Simple HTTP endpoint for integration
- ⚡ **Fast Processing**: In-memory tokenization for quick responses
- 🛡️ **Error Handling**: Comprehensive error handling and validation

## Quick Start

### 1. Set Up MongoDB Atlas

Before running the service, you need to set up a MongoDB Atlas account:

1. **Create a MongoDB Atlas Account**: Go to [https://www.mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas) and create a free account
2. **Create a Cluster**: Choose the free tier (M0)
3. **Create a Database User**: Go to Security → Database Access and create a user
4. **Get Connection String**: Go to Deployment → Connect → Connect your application
5. **Configure Network Access**: Add your IP address (or use `0.0.0.0/0` for development)

### 2. Configure Environment Variables

Create a `.env` file in the root directory:

```bash
cp env.example .env
```

Edit the `.env` file and add your MongoDB Atlas connection string:

```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/data-privacy-vault?retryWrites=true&w=majority
PORT=3001
NODE_ENV=development
```

Replace `username`, `password`, and `cluster` with your actual MongoDB Atlas credentials.

### 3. Install Dependencies

```bash
npm install
```

### 4. Start the Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will start on `http://localhost:3001`

**Note**: The service will work in in-memory mode if MongoDB is not configured, but tokens won't persist across server restarts.

### 5. Test the Service

```bash
npm test
```

## API Endpoints

### POST /anonymize

Anonymizes PII in a given message.

**Request:**
```bash
curl -X POST http://localhost:3001/anonymize \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"
```

**Response:**
```json
{
  "anonymizedMessage": "oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb"
}
```

### POST /deanonymize

Deanonymizes a message by converting tokens back to original PII values.

**Request:**
```bash
curl -X POST http://localhost:3001/deanonymize \
  -H "Content-Type: application/json" \
  -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

**Response:**
```json
{
  "message": "oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Data Privacy Vault",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /stats

Returns anonymization statistics.

**Response:**
```json
{
  "totalTokensGenerated": 42,
  "service": "Data Privacy Vault"
}
```

## PII Detection

The service detects the following types of PII:

### 📧 Email Addresses
- Supports standard email formats
- Pattern: `user@domain.com`

### 📱 Phone Numbers
- Supports various formats: `3152319157`, `+57 315 231 9157`, `(315) 231-9157`
- Validates digit count (7-15 digits)

### 👤 Names
- Detects capitalized words (potential names)
- Basic validation to reduce false positives
- Pattern: `Firstname Lastname`

## Tokenization

- **Algorithm**: SHA-256 hash truncated to 8 characters
- **Consistency**: Same PII value always produces the same token
- **Format**: Type prefix + lowercase alphanumeric (e.g., `EMAIL_a1b2c3d4`)
- **Reversibility**: Tokens can be reversed to original values using the `/deanonymize` endpoint
- **PII Types**: 
  - `NAME_` - For names
  - `EMAIL_` - For email addresses
  - `PHONE_` - For phone numbers

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Successful anonymization
- `400 Bad Request`: Invalid request format or missing message
- `500 Internal Server Error`: Server-side processing error

## Security Considerations

⚠️ **Important**: This is a basic implementation for demonstration purposes. For production use, consider:

- **Token Storage**: Implement secure token storage and retrieval
- **Advanced NLP**: Use more sophisticated name detection to reduce false positives
- **Logging**: Ensure no PII is logged in application logs
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **HTTPS**: Use HTTPS in production environments
- **Input Validation**: Add more comprehensive input validation

## Development

### Project Structure

```
data-privacy-vault/
├── server.js          # Main server file with anonymization logic
├── test.js            # Test suite
├── package.json       # Project configuration
└── README.md          # This file
```

### Adding New PII Types

To add detection for new PII types:

1. Add a new regex pattern to `PII_PATTERNS`
2. Add validation logic if needed
3. Update the `anonymizeMessage` function
4. Add tests for the new PII type

## License

MIT

```

```markdown
# Data Privacy Vault

A Node.js service for anonymizing Personally Identifiable Information (PII) using tokenization. This service detects names, emails, and phone numbers in text and replaces them with consistent alphanumeric tokens.

## Features

- 🔒 **PII Detection**: Automatically detects names, emails, and phone numbers
- 🎯 **Consistent Tokenization**: Same PII value always generates the same token
- 🚀 **RESTful API**: Simple HTTP endpoint for integration
- ⚡ **Fast Processing**: In-memory tokenization for quick responses
- 🛡️ **Error Handling**: Comprehensive error handling and validation

## Quick Start

### 1. Set Up MongoDB Atlas

Before running the service, you need to set up a MongoDB Atlas account:

1. **Create a MongoDB Atlas Account**: Go to [https://www.mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas) and create a free account
2. **Create a Cluster**: Choose the free tier (M0)
3. **Create a Database User**: Go to Security → Database Access and create a user
4. **Get Connection String**: Go to Deployment → Connect → Connect your application
5. **Configure Network Access**: Add your IP address (or use `0.0.0.0/0` for development)

### 2. Configure Environment Variables

Create a `.env` file in the root directory:

```bash
cp env.example .env
```

Edit the `.env` file and add your MongoDB Atlas connection string:

```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/data-privacy-vault?retryWrites=true&w=majority
PORT=3001
NODE_ENV=development
```

Replace `username`, `password`, and `cluster` with your actual MongoDB Atlas credentials.

### 3. Install Dependencies

```bash
npm install
```

### 4. Start the Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will start on `http://localhost:3001`

**Note**: The service will work in in-memory mode if MongoDB is not configured, but tokens won't persist across server restarts.

### 5. Test the Service

```bash
npm test
```

## API Endpoints

### POST /anonymize

Anonymizes PII in a given message.

**Request:**
```bash
curl -X POST http://localhost:3001/anonymize \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"
```

**Response:**
```json
{
  "anonymizedMessage": "oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb"
}
```

### POST /deanonymize

Deanonymizes a message by converting tokens back to original PII values.

**Request:**
```bash
curl -X POST http://localhost:3001/deanonymize \
  -H "Content-Type: application/json" \
  -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

**Response:**
```json
{
  "message": "oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Data Privacy Vault",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /stats

Returns anonymization statistics.

**Response:**
```json
{
  "totalTokensGenerated": 42,
  "service": "Data Privacy Vault"
}
```

## PII Detection

The service detects the following types of PII:

### 📧 Email Addresses
- Supports standard email formats
- Pattern: `user@domain.com`

### 📱 Phone Numbers
- Supports various formats: `3152319157`, `+57 315 231 9157`, `(315) 231-9157`
- Validates digit count (7-15 digits)

### 👤 Names
- Detects capitalized words (potential names)
- Basic validation to reduce false positives
- Pattern: `Firstname Lastname`

## Tokenization

- **Algorithm**: SHA-256 hash truncated to 8 characters
- **Consistency**: Same PII value always produces the same token
- **Format**: Type prefix + lowercase alphanumeric (e.g., `EMAIL_a1b2c3d4`)
- **Reversibility**: Tokens can be reversed to original values using the `/deanonymize` endpoint
- **PII Types**: 
  - `NAME_` - For names
  - `EMAIL_` - For email addresses
  - `PHONE_` - For phone numbers
- **Persistence**: Tokens are stored in MongoDB Atlas for persistence across server restarts
- **Performance**: In-memory cache for fast access, with MongoDB as the persistent store

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Successful anonymization
- `400 Bad Request`: Invalid request format or missing message
- `500 Internal Server Error`: Server-side processing error

## Security Considerations

⚠️ **Important**: This is a basic implementation for demonstration purposes. For production use, consider:

- **Token Storage**: Implement secure token storage and retrieval
- **Advanced NLP**: Use more sophisticated name detection to reduce false positives
- **Logging**: Ensure no PII is logged in application logs
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **HTTPS**: Use HTTPS in production environments
- **Input Validation**: Add more comprehensive input validation

## Development

### Project Structure

```
data-privacy-vault/
├── server.js          # Main server file with anonymization logic
├── test.js            # Test suite
├── package.json       # Project configuration
└── README.md          # This file
```

### Adding New PII Types

To add detection for new PII types:

1. Add a new regex pattern to `PII_PATTERNS`
2. Add validation logic if needed
3. Update the `anonymizeMessage` function
4. Add tests for the new PII type

## License

MIT

```

```markdown
# Data Privacy Vault

A Node.js service for anonymizing Personally Identifiable Information (PII) using tokenization. This service detects names, emails, and phone numbers in text and replaces them with consistent alphanumeric tokens.

## Features

- 🔒 **PII Detection**: Automatically detects names, emails, and phone numbers
- 🎯 **Consistent Tokenization**: Same PII value always generates the same token
- 🚀 **RESTful API**: Simple HTTP endpoint for integration
- ⚡ **Fast Processing**: In-memory tokenization for quick responses
- 🛡️ **Error Handling**: Comprehensive error handling and validation

## Quick Start

### 1. Set Up MongoDB Atlas

Before running the service, you need to set up a MongoDB Atlas account:

1. **Create a MongoDB Atlas Account**: Go to [https://www.mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas) and create a free account
2. **Create a Cluster**: Choose the free tier (M0)
3. **Create a Database User**: Go to Security → Database Access and create a user
4. **Get Connection String**: Go to Deployment → Connect → Connect your application
5. **Configure Network Access**: Add your IP address (or use `0.0.0.0/0` for development)

### 2. Configure Environment Variables

Create a `.env` file in the root directory:

```bash
cp env.example .env
```

Edit the `.env` file and add your MongoDB Atlas connection string:

```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/data-privacy-vault?retryWrites=true&w=majority
PORT=3001
NODE_ENV=development
```

Replace `username`, `password`, and `cluster` with your actual MongoDB Atlas credentials.

### 3. Install Dependencies

```bash
npm install
```

### 4. Start the Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will start on `http://localhost:3001`

**Note**: The service will work in in-memory mode if MongoDB is not configured, but tokens won't persist across server restarts.

### 5. Test the Service

```bash
npm test
```

## API Endpoints

### POST /anonymize

Anonymizes PII in a given message.

**Request:**
```bash
curl -X POST http://localhost:3001/anonymize \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"
```

**Response:**
```json
{
  "anonymizedMessage": "oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb"
}
```

### POST /deanonymize

Deanonymizes a message by converting tokens back to original PII values.

**Request:**
```bash
curl -X POST http://localhost:3001/deanonymize \
  -H "Content-Type: application/json" \
  -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

**Response:**
```json
{
  "message": "oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Data Privacy Vault",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /stats

Returns anonymization statistics.

**Response:**
```json
{
  "totalTokensGenerated": 42,
  "service": "Data Privacy Vault"
}
```

## PII Detection

The service detects the following types of PII:

### 📧 Email Addresses
- Supports standard email formats
- Pattern: `user@domain.com`

### 📱 Phone Numbers
- Supports various formats: `3152319157`, `+57 315 231 9157`, `(315) 231-9157`
- Validates digit count (7-15 digits)

### 👤 Names
- Detects capitalized words (potential names)
- Basic validation to reduce false positives
- Pattern: `Firstname Lastname`

## Tokenization

- **Algorithm**: SHA-256 hash truncated to 8 characters
- **Consistency**: Same PII value always produces the same token
- **Format**: Type prefix + lowercase alphanumeric (e.g., `EMAIL_a1b2c3d4`)
- **Reversibility**: Tokens can be reversed to original values using the `/deanonymize` endpoint
- **PII Types**: 
  - `NAME_` - For names
  - `EMAIL_` - For email addresses
  - `PHONE_` - For phone numbers
- **Persistence**: Tokens are stored in MongoDB Atlas for persistence across server restarts
- **Performance**: In-memory cache for fast access, with MongoDB as the persistent store

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Successful anonymization
- `400 Bad Request`: Invalid request format or missing message
- `500 Internal Server Error`: Server-side processing error

## MongoDB Atlas

The service uses MongoDB Atlas to persistently store token mappings. The database schema includes:

- **originalValue**: The original PII value (normalized to lowercase)
- **token**: The generated 8-character hash token
- **type**: The PII type ('NAME', 'EMAIL', or 'PHONE')
- **createdAt**: When the token was first created
- **lastUsedAt**: Last time the token was used
- **usageCount**: Number of times the token has been accessed

### Database Performance

The service uses a two-tier caching strategy:
1. **In-memory cache**: Fast access for frequently used tokens
2. **MongoDB Atlas**: Persistent storage for all tokens

On startup, the service loads all existing tokens into memory for fast access. New tokens are saved to both cache and database.

## Security Considerations

⚠️ **Important**: This is a basic implementation for demonstration purposes. For production use, consider:

- **Token Storage**: Tokens are stored in MongoDB Atlas with indexes for fast retrieval
- **Data Encryption**: Consider encrypting PII values before storing in MongoDB
- **Advanced NLP**: Use more sophisticated name detection to reduce false positives
- **Logging**: Ensure no PII is logged in application logs
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **HTTPS**: Use HTTPS in production environments
- **Input Validation**: Add more comprehensive input validation
- **Access Control**: Implement authentication and authorization for API access
- **Backup Strategy**: Implement regular database backups

## Development

### Project Structure

```
data-privacy-vault/
├── server.js          # Main server file with anonymization logic
├── test.js            # Test suite
├── package.json       # Project configuration
└── README.md          # This file
```

### Adding New PII Types

To add detection for new PII types:

1. Add a new regex pattern to `PII_PATTERNS`
2. Add validation logic if needed
3. Update the `anonymizeMessage` function
4. Add tests for the new PII type

## License

MIT

```

```markdown
# Data Privacy Vault

A Node.js service for anonymizing Personally Identifiable Information (PII) using tokenization. This service detects names, emails, and phone numbers in text and replaces them with consistent alphanumeric tokens.

## Features

- 🔒 **PII Detection**: Automatically detects names, emails, and phone numbers
- 🎯 **Consistent Tokenization**: Same PII value always generates the same token
- 🚀 **RESTful API**: Simple HTTP endpoint for integration
- ⚡ **Fast Processing**: In-memory tokenization for quick responses
- 🛡️ **Error Handling**: Comprehensive error handling and validation

## Quick Start

### 1. Set Up MongoDB Atlas

Before running the service, you need to set up a MongoDB Atlas account:

1. **Create a MongoDB Atlas Account**: Go to [https://www.mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas) and create a free account
2. **Create a Cluster**: Choose the free tier (M0)
3. **Create a Database User**: Go to Security → Database Access and create a user
4. **Get Connection String**: Go to Deployment → Connect → Connect your application
5. **Configure Network Access**: Add your IP address (or use `0.0.0.0/0` for development)

### 2. Configure Environment Variables

Create a `.env` file in the root directory:

```bash
cp env.example .env
```

Edit the `.env` file and add your MongoDB Atlas connection string:

```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/data-privacy-vault?retryWrites=true&w=majority
PORT=3001
NODE_ENV=development
```

Replace `username`, `password`, and `cluster` with your actual MongoDB Atlas credentials.

### 3. Install Dependencies

```bash
npm install
```

### 4. Start the Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will start on `http://localhost:3001`

**Note**: The service will work in in-memory mode if MongoDB is not configured, but tokens won't persist across server restarts.

### 5. Test the Service

```bash
npm test
```

## API Endpoints

### POST /anonymize

Anonymizes PII in a given message.

**Request:**
```bash
curl -X POST http://localhost:3001/anonymize \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"
```

**Response:**
```json
{
  "anonymizedMessage": "oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb"
}
```

### POST /deanonymize

Deanonymizes a message by converting tokens back to original PII values.

**Request:**
```bash
curl -X POST http://localhost:3001/deanonymize \
  -H "Content-Type: application/json" \
  -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

**Response:**
```json
{
  "message": "oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Data Privacy Vault",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /stats

Returns anonymization statistics.

**Response:**
```json
{
  "totalTokensGenerated": 42,
  "service": "Data Privacy Vault"
}
```

## PII Detection

The service detects the following types of PII:

### 📧 Email Addresses
- Supports standard email formats
- Pattern: `user@domain.com`

### 📱 Phone Numbers
- Supports various formats: `3152319157`, `+57 315 231 9157`, `(315) 231-9157`
- Validates digit count (7-15 digits)

### 👤 Names
- Detects capitalized words (potential names)
- Basic validation to reduce false positives
- Pattern: `Firstname Lastname`

## Tokenization

- **Algorithm**: SHA-256 hash truncated to 8 characters
- **Consistency**: Same PII value always produces the same token
- **Format**: Type prefix + lowercase alphanumeric (e.g., `EMAIL_a1b2c3d4`)
- **Reversibility**: Tokens can be reversed to original values using the `/deanonymize` endpoint
- **PII Types**: 
  - `NAME_` - For names
  - `EMAIL_` - For email addresses
  - `PHONE_` - For phone numbers
- **Persistence**: Tokens are stored in MongoDB Atlas for persistence across server restarts
- **Performance**: In-memory cache for fast access, with MongoDB as the persistent store

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Successful anonymization
- `400 Bad Request`: Invalid request format or missing message
- `500 Internal Server Error`: Server-side processing error

## MongoDB Atlas

The service uses MongoDB Atlas to persistently store token mappings. The database schema includes:

- **originalValue**: The original PII value (normalized to lowercase)
- **token**: The generated 8-character hash token
- **type**: The PII type ('NAME', 'EMAIL', or 'PHONE')
- **createdAt**: When the token was first created
- **lastUsedAt**: Last time the token was used
- **usageCount**: Number of times the token has been accessed

### Database Performance

The service uses a two-tier caching strategy:
1. **In-memory cache**: Fast access for frequently used tokens
2. **MongoDB Atlas**: Persistent storage for all tokens

On startup, the service loads all existing tokens into memory for fast access. New tokens are saved to both cache and database.

## Security Considerations

⚠️ **Important**: This is a basic implementation for demonstration purposes. For production use, consider:

- **Token Storage**: Tokens are stored in MongoDB Atlas with indexes for fast retrieval
- **Data Encryption**: Consider encrypting PII values before storing in MongoDB
- **Advanced NLP**: Use more sophisticated name detection to reduce false positives
- **Logging**: Ensure no PII is logged in application logs
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **HTTPS**: Use HTTPS in production environments
- **Input Validation**: Add more comprehensive input validation
- **Access Control**: Implement authentication and authorization for API access
- **Backup Strategy**: Implement regular database backups

## Development

### Project Structure

```
data-privacy-vault/
├── server.js          # Main server file with anonymization logic
├── test.js            # Test suite
├── test_deanonymize.js # Deanonymization tests
├── package.json       # Project configuration
├── env.example        # Environment variables template
├── models/
│   └── Token.js       # MongoDB schema for tokens
├── .env               # Environment variables (create from env.example)
└── README.md          # This file
```

### Adding New PII Types

To add detection for new PII types:

1. Add a new regex pattern to `PII_PATTERNS`
2. Add validation logic if needed
3. Update the `anonymizeMessage` function
4. Add tests for the new PII type

## License

MIT

```

Agregando un archivo .gitignore para proteger credenciales:


```ignore
# Dependencies
node_modules/

# Environment variables
.env

# Logs
logs/
*.log
npm-debug.log*

# OS files
.DS_Store
Thumbs.db

# Editor files
.vscode/
.idea/
*.swp
*.swo

# Temporary files
*.tmp
*.temp
```

Creando un archivo con instrucciones detalladas para configurar MongoDB Atlas:


```markdown
# MongoDB Atlas Setup Guide

This guide will help you set up MongoDB Atlas for the Data Privacy Vault application.

## Step 1: Create MongoDB Atlas Account

1. Go to [https://www.mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas)
2. Click "Try Free" and sign up for a free account
3. Verify your email address

## Step 2: Create a Free Cluster

1. After logging in, you'll be prompted to create a cluster
2. Choose the **FREE** (M0) tier
3. Select your preferred cloud provider and region:
   - **AWS**, **Google Cloud**, or **Azure**
   - Choose a region close to you for better performance
   - Example: `N. Virginia (us-east-1)` or `Frankfurt (eu-central-1)`
4. Give your cluster a name (e.g., `DataPrivacyVault`)
5. Click "Create Cluster"

**Note**: It takes about 3-5 minutes for the cluster to be created.

## Step 3: Create a Database User

1. Go to **Security** → **Database Access** (in the left sidebar)
2. Click "Add New Database User"
3. Choose "Password" as the authentication method
4. Create a username and password:
   - **Username**: `data-privacy-vault` (or your preferred username)
   - **Password**: Generate a strong password (save it somewhere safe!)
5. Under "Database User Privileges", select "Read and write to any database"
6. Click "Add User"

**Important**: Save your username and password! You'll need them for the connection string.

## Step 4: Configure Network Access

1. Go to **Security** → **Network Access** (in the left sidebar)
2. Click "Add IP Address"
3. Choose one of the following:
   - **Option A (Development)**: Click "Allow Access from Anywhere" → This sets IP to `0.0.0.0/0`
   - **Option B (Production)**: Click "Add Current IP Address" → This only allows your current IP
4. Click "Confirm"

**Recommendation**: For development, use Option A. For production, use Option B and add specific IPs.

## Step 5: Get Your Connection String

1. Go to **Deployment** → **Database** (in the left sidebar)
2. Click "Connect" on your cluster
3. Select "Connect your application"
4. Choose your driver version:
   - **Driver**: Node.js
   - **Version**: 5.5 or later
5. Copy the connection string:
   ```
   mongodb+srv://<username>:<password>@cluster.mongodb.net/?retryWrites=true&w=majority
   ```

## Step 6: Configure Your Application

1. Create a `.env` file in your project root:
   ```bash
   cp env.example .env
   ```

2. Edit the `.env` file:
   ```env
   MONGODB_URI=mongodb+srv://data-privacy-vault:YOUR_PASSWORD@cluster.mongodb.net/data-privacy-vault?retryWrites=true&w=majority
   PORT=3001
   NODE_ENV=development
   ```

   **Replace:**
   - `data-privacy-vault` with your database username
   - `YOUR_PASSWORD` with your database password
   - `cluster` with your actual cluster name
   - The database name `data-privacy-vault` can be changed if needed

3. Save the file

## Step 7: Test the Connection

1. Start your application:
   ```bash
   npm start
   ```

2. Look for these messages in the console:
   ```
   ✅ MongoDB Atlas connected: cluster...
   📊 Database: data-privacy-vault
   📦 Loaded X tokens into memory cache
   ```

If you see these messages, your MongoDB connection is successful!

## Troubleshooting

### Connection Error: "Authentication failed"

- Check that your username and password in the `.env` file match your MongoDB Atlas database user
- Make sure special characters in your password are URL-encoded (e.g., `@` becomes `%40`)

### Connection Error: "IP not whitelisted"

- Go to **Network Access** and add your current IP address
- Or use `0.0.0.0/0` for development (not recommended for production)

### Connection Error: "DNS lookup failed"

- Check your internet connection
- Verify the connection string is correct
- Make sure the cluster is fully provisioned (check the cluster status)

### Connection Timeout

- Check your firewall settings
- Verify network access settings in MongoDB Atlas
- Try changing your cluster region

## Free Tier Limitations

The MongoDB Atlas free tier (M0) includes:
- 512 MB storage
- Shared CPU and RAM
- Unlimited databases and collections
- Basic monitoring

**Note**: For production use with high traffic, consider upgrading to a paid tier.

## Additional Resources

- [MongoDB Atlas Documentation](https://docs.atlas.mongodb.com/)
- [Connection String Guide](https://docs.atlas.mongodb.com/getting-started/)
- [Troubleshooting Guide](https://docs.atlas.mongodb.com/troubleshooting-connection/)

## Security Best Practices

1. **Never commit your `.env` file** to version control
2. **Use strong passwords** for your database user
3. **Restrict IP access** in production (avoid `0.0.0.0/0`)
4. **Enable audit logging** for production deployments
5. **Regular backups**: Set up automatic backups for production data
6. **Encryption at rest**: Enable encryption for sensitive data

## Need Help?

If you encounter issues:
1. Check the MongoDB Atlas Status page: https://status.mongodb.com/
2. Review the MongoDB Community Forums: https://www.mongodb.com/community/forums/
3. Check your application logs for detailed error messages
```

Implementación completada.

## Resumen de los cambios

### Archivos nuevos
1. `models/Token.js` — modelo Mongoose con índices
2. `env.example` — plantilla de variables de entorno
3. `MONGODB_SETUP.md` — guía de configuración
4. `.gitignore` — protección de credenciales

### Archivos modificados
1. `package.json` — agregados mongoose y dotenv
2. `server.js` — integración con MongoDB Atlas
3. `README.md` — instrucciones de configuración

## Características implementadas

### Persistencia en MongoDB
- Guarda los pares (valor original, token)
- Persistencia tras reinicios del servidor
- Recuperación de tokens históricos

### Cache en memoria
- Carga de tokens existentes al arranque
- Cacheo para acceso rápido
- Fallback si no hay conexión a MongoDB

### Estadísticas y monitoreo
- Endpoint `/stats` para métricas
- Indicador de estado de conexión a MongoDB
- Contadores de tokens en BD y memoria

## Próximos pasos

### Instalar dependencias
```bash
npm install
```

### Configurar MongoDB Atlas
1. Seguir `MONGODB_SETUP.md`
2. Crear un `.env` con la cadena de conexión

### Iniciar el servidor
```bash
npm start
```

### Probar
```bash
# Anonymize
curl -X POST http://localhost:3001/anonymize -H "Content-Type: application/json" -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"

# Deanonymize
curl -X POST http://localhost:3001/deanonymize -H "Content-Type: application/json" -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

## Flujo de funcionamiento
1. Anonimización:
   - Detecta PII en el mensaje
   - Consulta cache en memoria
   - Si no existe, consulta MongoDB
   - Si no existe, genera nuevo token
   - Guarda en MongoDB y en cache
   - Retorna mensaje anonimizado

2. Desanonimización:
   - Extrae tokens del mensaje
   - Busca en cache en memoria
   - Si no existe, consulta MongoDB
   - Carga en cache para futuras consultas
   - Actualiza estadísticas de uso
   - Retorna mensaje original

¿Revisamos algún archivo específico o necesitas aclaraciones sobre la integración con MongoDB Atlas?

```shellscript
npm install
```

```shellscript
npm start
```

```shellscript
# Anonymize
curl -X POST http://localhost:3001/anonymize -H "Content-Type: application/json" -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"

# Deanonymize
curl -X POST http://localhost:3001/deanonymize -H "Content-Type: application/json" -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

---

**User**

this error raised: Error: Cannot find module 'mongoose'

---

**Cursor**

Likely dependencies weren’t installed. On Windows PowerShell, use npm.cmd.

Do this in your project folder:
- Verify you’re in the right dir:
  - cd "C:\Users\User\Documents\Cursor\Taller2-3"
- Install deps:
  - npm.cmd install
- If the error persists, install the missing packages explicitly:
  - npm.cmd install mongoose dotenv
- Then restart the server:
  - npm.cmd start

If it still fails:
- Clean and reinstall:
  - Remove the `node_modules` folder and any lock file (`package-lock.json`)
  - npm.cmd install
- Confirm `mongoose` is listed under dependencies in `package.json`.
- Ensure the import exists at the top of `server.js`:
  - `const mongoose = require('mongoose');`
- Restart the server after installing.

---

**User**

I have just configured mongo connection, but I got this error:
Error checking MongoDB for existing token: Operation `tokens.findOne()` buffering timed out after 10000m

---

**Cursor**

I see the MongoDB query is timing out because Mongoose is trying to buffer operations before the connection is established. I’ll update the code to: (1) skip DB queries when not connected, (2) disable Mongoose command buffering, and (3) make the connection logic more robust. Then you can retry without hitting timeouts.

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Disable mongoose buffering so ops fail fast when disconnected instead of timing out
mongoose.set('bufferCommands', false);

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    if (mongoose.connection.readyState !== 1) {
      return;
    }
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Helper to check if DB is connected
 */
function isDbConnected() {
  return mongoose.connection.readyState === 1; // 1 = connected
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  try {
    const existingDoc = await Token.findByOriginalValue(normalizedValue);
    
    if (existingDoc) {
      // Token exists in database - load into cache
      const token = existingDoc.token;
      const docType = existingDoc.type;
      
      // Populate caches
      tokenCache.set(normalizedValue, token);
      reverseTokenCache.set(token, { value: normalizedValue, type: docType });
      
      return `${docType}_${token}`;
    }
  } catch (error) {
    console.error('Error checking MongoDB for existing token:', error.message);
    // Continue to generate new token
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence
  try {
    const newToken = new Token({
      originalValue: normalizedValue,
      token: token,
      type: type
    });
    
    await newToken.save();
    console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
    
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key error - token already exists (race condition)
      console.warn(`Token ${token} already exists in database`);
    } else {
      console.error('Error saving token to MongoDB:', error.message);
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB
    if (!originalData) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server and connect to database
(async () => {
  // Connect to MongoDB Atlas
  await connectDatabase();
  
  // Start the Express server
  app.listen(PORT, () => {
    console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
    console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
    console.log(`📈 Stats endpoint: GET http://localhost:${PORT}/stats`);
  });
})();

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Disable mongoose buffering so ops fail fast when disconnected instead of timing out
mongoose.set('bufferCommands', false);

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    if (mongoose.connection.readyState !== 1) {
      return;
    }
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Helper to check if DB is connected
 */
function isDbConnected() {
  return mongoose.connection.readyState === 1; // 1 = connected
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  if (isDbConnected()) {
    try {
      const existingDoc = await Token.findByOriginalValue(normalizedValue);
      
      if (existingDoc) {
        // Token exists in database - load into cache
        const token = existingDoc.token;
        const docType = existingDoc.type;
        
        // Populate caches
        tokenCache.set(normalizedValue, token);
        reverseTokenCache.set(token, { value: normalizedValue, type: docType });
        
        return `${docType}_${token}`;
      }
    } catch (error) {
      console.error('Error checking MongoDB for existing token:', error.message);
      // Continue to generate new token
    }
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence (if connected)
  if (isDbConnected()) {
    try {
      const newToken = new Token({
        originalValue: normalizedValue,
        token: token,
        type: type
      });
      
      await newToken.save();
      console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
      
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error - token already exists (race condition)
        console.warn(`Token ${token} already exists in database`);
      } else {
        console.error('Error saving token to MongoDB:', error.message);
      }
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB
    if (!originalData) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server and connect to database
(async () => {
  // Connect to MongoDB Atlas
  await connectDatabase();
  
  // Start the Express server
  app.listen(PORT, () => {
    console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
    console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
    console.log(`📈 Stats endpoint: GET http://localhost:${PORT}/stats`);
  });
})();

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Disable mongoose buffering so ops fail fast when disconnected instead of timing out
mongoose.set('bufferCommands', false);

const Token = require('./models/Token');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    if (mongoose.connection.readyState !== 1) {
      return;
    }
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Helper to check if DB is connected
 */
function isDbConnected() {
  return mongoose.connection.readyState === 1; // 1 = connected
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  if (isDbConnected()) {
    try {
      const existingDoc = await Token.findByOriginalValue(normalizedValue);
      
      if (existingDoc) {
        // Token exists in database - load into cache
        const token = existingDoc.token;
        const docType = existingDoc.type;
        
        // Populate caches
        tokenCache.set(normalizedValue, token);
        reverseTokenCache.set(token, { value: normalizedValue, type: docType });
        
        return `${docType}_${token}`;
      }
    } catch (error) {
      console.error('Error checking MongoDB for existing token:', error.message);
      // Continue to generate new token
    }
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence (if connected)
  if (isDbConnected()) {
    try {
      const newToken = new Token({
        originalValue: normalizedValue,
        token: token,
        type: type
      });
      
      await newToken.save();
      console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
      
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error - token already exists (race condition)
        console.warn(`Token ${token} already exists in database`);
      } else {
        console.error('Error saving token to MongoDB:', error.message);
      }
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB (only if connected)
    if (!originalData && isDbConnected()) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server and connect to database
(async () => {
  // Connect to MongoDB Atlas
  await connectDatabase();
  
  // Start the Express server
  app.listen(PORT, () => {
    console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
    console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
    console.log(`📈 Stats endpoint: GET http://localhost:${PORT}/stats`);
  });
})();

module.exports = app;


```

- I updated the service to avoid Mongoose “buffering timed out” errors by skipping DB queries when not connected and disabling buffering. You can restart and try again.

Do this:
1) Ensure env file is loaded
- Use .env (not mongo.env) in the project root, or set MONGODB_URI in your environment before starting.
- If you want to keep using mongo.env, rename/copy it to .env.

2) Install deps using npm.cmd on Windows
- cd "C:\Users\User\Documents\Cursor\Taller2-3"
- npm.cmd install
- npm.cmd start

What changed in code:
- Disabled Mongoose command buffering so ops don’t hang:
  - globally: mongoose.set('bufferCommands', false)
- Guarded DB usage with connection checks:
  - generateToken and deanonymizeMessage now only query/save to MongoDB if mongoose.connection.readyState === 1
  - loadTokensIntoCache bails out if not connected
- Added isDbConnected() helper
- Kept in-memory caches as a reliable fallback

If you still see errors:
- Verify MONGODB_URI is correct and URL-encoded (special chars in password must be encoded).
- In Atlas, add your client IP in Network Access and wait a minute after changes.
- Your cluster must be “Running” (not provisioning).
- Try a quick connectivity test using mongosh from your machine with the same URI.

Once connected, /anonymize will persist tokens and /deanonymize will resolve them from MongoDB (and cache).

---

**User**

I have just realized, when the app started, that I had this message:   Warning: MONGODB_URI not set. Running in in-memory mode only.
But, I have the file mongo.env with this setting:
MONGODB_URI=mongodb+srv://rodher:Toti1205@clusterhdrs.tulrx4y.mongodb.net/rodher?retryWrites=true&w=majority
what is the reason of these issue?

---

**Cursor**

The app didn’t find MONGODB_URI because dotenv only auto-loads a file named .env in the project root. Your file is mongo.env, so it’s never read.

Pick one fix:

- Easiest: rename the file
  - Rename mongo.env to .env in the project root
  - Restart: npm.cmd start

- Keep mongo.env: load it explicitly
  - In server.js, change the dotenv load to:
    ```javascript
    require('dotenv').config({ path: 'mongo.env' });
    ```
  - Restart the app

- Set the variable in your shell (temporary for that session)
  - PowerShell:
    ```powershell
    $env:MONGODB_URI="mongodb+srv://...your-uri..."
    npm.cmd start
    ```

- Set via script
  - Update the start script to use the env var:
    ```powershell
    setx MONGODB_URI "mongodb+srv://...your-uri..."
    # then open a NEW PowerShell so the env refreshes
    npm.cmd start
    ```

Tips:
- Ensure you start the app from the project root where the env file lives.
- If your password has special characters, URL-encode them in the URI.

```javascript
    require('dotenv').config({ path: 'mongo.env' });
    ```
  - Restart the app

- Set the variable in your shell (temporary for that session)
  - PowerShell:
    ```powershell
    $env:MONGODB_URI="mongodb+srv://...your-uri..."
    npm.cmd start
    ```

- Set via script
  - Update the start script to use the env var:
    ```powershell
    setx MONGODB_URI "mongodb+srv://...your-uri..."
    # then open a NEW PowerShell so the env refreshes
    npm.cmd start
    ```

Tips:
- Ensure you start the app from the project root where the env file lives.
- If your password has special characters, URL-encode them in the URI.
```

```powershell
    $env:MONGODB_URI="mongodb+srv://...your-uri..."
    npm.cmd start
```

```powershell
    setx MONGODB_URI "mongodb+srv://...your-uri..."
    # then open a NEW PowerShell so the env refreshes
    npm.cmd start
```

---

**User**

I am confused,. the database I have in mongo is named test, bit a new database was created with the name of my username.. why ?

---

**Cursor**

Short answer: because your connection string names that database.

- You used a URI like:
  mongodb+srv://.../rodher?retryWrites=true&w=majority
  The path segment after the host (here `rodher`) is the database Mongoose uses. On first write, MongoDB creates it if it doesn’t exist.

- If you want the `test` database, use:
  mongodb+srv://.../test?retryWrites=true&w=majority
  or set it via code:
  mongoose.connect(MONGODB_URI, { dbName: 'test' })

What to do:
- Update your env to point to test:
  MONGODB_URI=mongodb+srv://<user>:<pass>@<cluster>.mongodb.net/test?retryWrites=true&w=majority
- Restart the app.

Notes:
- MongoDB creates databases lazily (on first write).
- In our logs we print the connected DB name; that’s the one from your URI.

---

**User**

It works!! Now, Please create a class to connect to an OpenAI account and implement a text completion

---

**Cursor**

I'll add an OpenAI client class, wire an endpoint to call it, and update config and docs. Then you can set OPENAI_API_KEY and test.

```json
{
  "name": "data-privacy-vault",
  "version": "1.0.0",
  "description": "A Node.js service for anonymizing PII data using tokenization",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "node test.js"
  },
  "keywords": ["privacy", "anonymization", "pii", "data-protection"],
  "author": "",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "crypto": "^1.0.1",
    "cors": "^2.8.5",
    "mongoose": "^8.0.3",
    "dotenv": "^16.3.1",
    "openai": "^4.57.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}


```

```plaintext
# MongoDB Atlas Connection String
# Replace with your actual MongoDB Atlas connection string
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/data-privacy-vault?retryWrites=true&w=majority

# Server Configuration
PORT=3001

# Node Environment
NODE_ENV=development

# OpenAI API
OPENAI_API_KEY=your-openai-api-key

```

```javascript
const OpenAI = require('openai');

/**
 * OpenAIClient
 * Thin wrapper around OpenAI SDK for text completion.
 */
class OpenAIClient {
  /**
   * @param {object} options
   * @param {string} [options.apiKey] - OpenAI API key. Falls back to process.env.OPENAI_API_KEY
   * @param {string} [options.defaultModel] - Default model to use for completions
   */
  constructor({ apiKey, defaultModel } = {}) {
    const resolvedKey = apiKey || process.env.OPENAI_API_KEY;
    if (!resolvedKey) {
      throw new Error('OPENAI_API_KEY is required. Set it in environment variables.');
    }

    this.client = new OpenAI({ apiKey: resolvedKey });
    this.defaultModel = defaultModel || 'gpt-4o-mini';
  }

  /**
   * Create a text completion using Chat Completions API
   * @param {string} prompt - The user prompt
   * @param {object} options
   * @param {string} [options.model] - Model override
   * @param {number} [options.temperature] - Sampling temperature (0-2)
   * @param {number} [options.maxTokens] - Max tokens in the response
   * @returns {Promise<string>} - The generated text
   */
  async completeText(prompt, { model, temperature = 0.7, maxTokens = 256 } = {}) {
    if (typeof prompt !== 'string' || prompt.trim().length === 0) {
      throw new Error('Prompt must be a non-empty string.');
    }

    const chosenModel = model || this.defaultModel;

    const response = await this.client.chat.completions.create({
      model: chosenModel,
      messages: [
        { role: 'system', content: 'You are a helpful assistant.' },
        { role: 'user', content: prompt }
      ],
      temperature,
      max_tokens: maxTokens
    });

    const text = response.choices?.[0]?.message?.content?.trim() || '';
    return text;
  }
}

module.exports = OpenAIClient;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Disable mongoose buffering so ops fail fast when disconnected instead of timing out
mongoose.set('bufferCommands', false);

const Token = require('./models/Token');
const OpenAIClient = require('./services/OpenAIClient');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    if (mongoose.connection.readyState !== 1) {
      return;
    }
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Helper to check if DB is connected
 */
function isDbConnected() {
  return mongoose.connection.readyState === 1; // 1 = connected
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  if (isDbConnected()) {
    try {
      const existingDoc = await Token.findByOriginalValue(normalizedValue);
      
      if (existingDoc) {
        // Token exists in database - load into cache
        const token = existingDoc.token;
        const docType = existingDoc.type;
        
        // Populate caches
        tokenCache.set(normalizedValue, token);
        reverseTokenCache.set(token, { value: normalizedValue, type: docType });
        
        return `${docType}_${token}`;
      }
    } catch (error) {
      console.error('Error checking MongoDB for existing token:', error.message);
      // Continue to generate new token
    }
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence (if connected)
  if (isDbConnected()) {
    try {
      const newToken = new Token({
        originalValue: normalizedValue,
        token: token,
        type: type
      });
      
      await newToken.save();
      console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
      
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error - token already exists (race condition)
        console.warn(`Token ${token} already exists in database`);
      } else {
        console.error('Error saving token to MongoDB:', error.message);
      }
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB (only if connected)
    if (!originalData && isDbConnected()) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server and connect to database
(async () => {
  // Connect to MongoDB Atlas
  await connectDatabase();
  
  // Start the Express server
  app.listen(PORT, () => {
    console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
    console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
    console.log(`📈 Stats endpoint: GET http://localhost:${PORT}/stats`);
  });
})();

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Disable mongoose buffering so ops fail fast when disconnected instead of timing out
mongoose.set('bufferCommands', false);

const Token = require('./models/Token');
const OpenAIClient = require('./services/OpenAIClient');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    if (mongoose.connection.readyState !== 1) {
      return;
    }
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Helper to check if DB is connected
 */
function isDbConnected() {
  return mongoose.connection.readyState === 1; // 1 = connected
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  if (isDbConnected()) {
    try {
      const existingDoc = await Token.findByOriginalValue(normalizedValue);
      
      if (existingDoc) {
        // Token exists in database - load into cache
        const token = existingDoc.token;
        const docType = existingDoc.type;
        
        // Populate caches
        tokenCache.set(normalizedValue, token);
        reverseTokenCache.set(token, { value: normalizedValue, type: docType });
        
        return `${docType}_${token}`;
      }
    } catch (error) {
      console.error('Error checking MongoDB for existing token:', error.message);
      // Continue to generate new token
    }
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence (if connected)
  if (isDbConnected()) {
    try {
      const newToken = new Token({
        originalValue: normalizedValue,
        token: token,
        type: type
      });
      
      await newToken.save();
      console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
      
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error - token already exists (race condition)
        console.warn(`Token ${token} already exists in database`);
      } else {
        console.error('Error saving token to MongoDB:', error.message);
      }
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB (only if connected)
    if (!originalData && isDbConnected()) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server and connect to database
(async () => {
  // Connect to MongoDB Atlas
  await connectDatabase();
  
  // Initialize OpenAI only if key is present
  let openAI;
  try {
    if (process.env.OPENAI_API_KEY) {
      openAI = new OpenAIClient({});
      console.log('🤖 OpenAI client initialized');
    } else {
      console.warn('⚠️  OPENAI_API_KEY not set. /complete endpoint will return 501.');
    }
  } catch (e) {
    console.error('Failed to initialize OpenAI client:', e.message);
  }

  // POST /complete - text completion via OpenAI
  app.post('/complete', async (req, res) => {
    try {
      if (!openAI) {
        return res.status(501).json({
          error: 'Not Implemented',
          details: 'OpenAI is not configured on this server'
        });
      }

      const { prompt, model, temperature, maxTokens } = req.body || {};
      if (!prompt || typeof prompt !== 'string') {
        return res.status(400).json({
          error: 'Bad Request',
          details: 'prompt (string) is required'
        });
      }

      const text = await openAI.completeText(prompt, { model, temperature, maxTokens });
      return res.json({ completion: text });
    } catch (error) {
      console.error('Error in /complete endpoint:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        details: 'Failed to generate completion'
      });
    }
  });

  // Start the Express server
  app.listen(PORT, () => {
    console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
    console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
    console.log(`💬 Completion endpoint: POST http://localhost:${PORT}/complete`);
    console.log(`📈 Stats endpoint: GET http://localhost:${PORT}/stats`);
  });
})();

module.exports = app;


```

```markdown
# Data Privacy Vault

A Node.js service for anonymizing Personally Identifiable Information (PII) using tokenization. This service detects names, emails, and phone numbers in text and replaces them with consistent alphanumeric tokens.

## Features

- 🔒 **PII Detection**: Automatically detects names, emails, and phone numbers
- 🎯 **Consistent Tokenization**: Same PII value always generates the same token
- 🚀 **RESTful API**: Simple HTTP endpoint for integration
- ⚡ **Fast Processing**: In-memory tokenization for quick responses
- 🛡️ **Error Handling**: Comprehensive error handling and validation

## Quick Start

### 1. Set Up MongoDB Atlas

Before running the service, you need to set up a MongoDB Atlas account:

1. **Create a MongoDB Atlas Account**: Go to [https://www.mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas) and create a free account
2. **Create a Cluster**: Choose the free tier (M0)
3. **Create a Database User**: Go to Security → Database Access and create a user
4. **Get Connection String**: Go to Deployment → Connect → Connect your application
5. **Configure Network Access**: Add your IP address (or use `0.0.0.0/0` for development)

### 2. Configure Environment Variables

Create a `.env` file in the root directory:

```bash
cp env.example .env
```

Edit the `.env` file and add your MongoDB Atlas connection string:

```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/data-privacy-vault?retryWrites=true&w=majority
PORT=3001
NODE_ENV=development
```

Replace `username`, `password`, and `cluster` with your actual MongoDB Atlas credentials.

### 3. Install Dependencies

```bash
npm install
```

### 4. Start the Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will start on `http://localhost:3001`

**Note**: The service will work in in-memory mode if MongoDB is not configured, but tokens won't persist across server restarts.

### 5. Test the Service

```bash
npm test
```

## API Endpoints

### POST /anonymize

Anonymizes PII in a given message.

**Request:**
```bash
curl -X POST http://localhost:3001/anonymize \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157\"}"
```

**Response:**
```json
{
  "anonymizedMessage": "oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb"
}
```

### POST /deanonymize

Deanonymizes a message by converting tokens back to original PII values.

**Request:**
```bash
curl -X POST http://localhost:3001/deanonymize \
  -H "Content-Type: application/json" \
  -d "{\"anonymizedMessage\":\"oferta de trabajo para NAME_e1be92e2b3a5 con email EMAIL_8004719c6ea5 y teléfono PHONE_40e83067b9cb\"}"
```

**Response:**
```json
{
  "message": "oferta de trabajo para Dago Borda con email dborda@gmail.com y teléfono 3152319157"
}
```

### POST /complete

Generates a text completion using OpenAI.

Environment: set `OPENAI_API_KEY` in `.env`.

**Request:**
```bash
curl -X POST http://localhost:3001/complete \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"
```

Optional JSON fields: `model`, `temperature`, `maxTokens`.

**Response:**
```json
{
  "completion": "¡Hola! Espero que estés teniendo un excelente día."
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Data Privacy Vault",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /stats

Returns anonymization statistics.

**Response:**
```json
{
  "totalTokensGenerated": 42,
  "service": "Data Privacy Vault"
}
```

## PII Detection

The service detects the following types of PII:

### 📧 Email Addresses
- Supports standard email formats
- Pattern: `user@domain.com`

### 📱 Phone Numbers
- Supports various formats: `3152319157`, `+57 315 231 9157`, `(315) 231-9157`
- Validates digit count (7-15 digits)

### 👤 Names
- Detects capitalized words (potential names)
- Basic validation to reduce false positives
- Pattern: `Firstname Lastname`

## Tokenization

- **Algorithm**: SHA-256 hash truncated to 8 characters
- **Consistency**: Same PII value always produces the same token
- **Format**: Type prefix + lowercase alphanumeric (e.g., `EMAIL_a1b2c3d4`)
- **Reversibility**: Tokens can be reversed to original values using the `/deanonymize` endpoint
- **PII Types**: 
  - `NAME_` - For names
  - `EMAIL_` - For email addresses
  - `PHONE_` - For phone numbers
- **Persistence**: Tokens are stored in MongoDB Atlas for persistence across server restarts
- **Performance**: In-memory cache for fast access, with MongoDB as the persistent store

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: Successful anonymization
- `400 Bad Request`: Invalid request format or missing message
- `500 Internal Server Error`: Server-side processing error

## MongoDB Atlas

The service uses MongoDB Atlas to persistently store token mappings. The database schema includes:

- **originalValue**: The original PII value (normalized to lowercase)
- **token**: The generated 8-character hash token
- **type**: The PII type ('NAME', 'EMAIL', or 'PHONE')
- **createdAt**: When the token was first created
- **lastUsedAt**: Last time the token was used
- **usageCount**: Number of times the token has been accessed

### Database Performance

The service uses a two-tier caching strategy:
1. **In-memory cache**: Fast access for frequently used tokens
2. **MongoDB Atlas**: Persistent storage for all tokens

On startup, the service loads all existing tokens into memory for fast access. New tokens are saved to both cache and database.

## Security Considerations

⚠️ **Important**: This is a basic implementation for demonstration purposes. For production use, consider:

- **Token Storage**: Tokens are stored in MongoDB Atlas with indexes for fast retrieval
- **Data Encryption**: Consider encrypting PII values before storing in MongoDB
- **Advanced NLP**: Use more sophisticated name detection to reduce false positives
- **Logging**: Ensure no PII is logged in application logs
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **HTTPS**: Use HTTPS in production environments
- **Input Validation**: Add more comprehensive input validation
- **Access Control**: Implement authentication and authorization for API access
- **Backup Strategy**: Implement regular database backups

## Development

### Project Structure

```
data-privacy-vault/
├── server.js          # Main server file with anonymization logic
├── test.js            # Test suite
├── test_deanonymize.js # Deanonymization tests
├── package.json       # Project configuration
├── env.example        # Environment variables template
├── models/
│   └── Token.js       # MongoDB schema for tokens
├── .env               # Environment variables (create from env.example)
└── README.md          # This file
```

### Adding New PII Types

To add detection for new PII types:

1. Add a new regex pattern to `PII_PATTERNS`
2. Add validation logic if needed
3. Update the `anonymizeMessage` function
4. Add tests for the new PII type

## License

MIT

```

- I added an OpenAI client class and a POST /complete endpoint. Set OPENAI_API_KEY in your env and install the SDK.

What to do:
- Add your key:
  - In `.env`: OPENAI_API_KEY=sk-...
- Install deps (Windows):
  - cd "C:\Users\User\Documents\Cursor\Taller2-3"
  - npm.cmd install
- Start server:
  - npm.cmd start

Test:
```bash
curl -X POST http://localhost:3001/complete \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"
```

Files added/updated:
- services/OpenAIClient.js: wrapper with completeText(prompt, { model, temperature, maxTokens })
- server.js: initializes OpenAI if OPENAI_API_KEY is set; adds POST /complete
- package.json: adds openai dependency
- env.example: adds OPENAI_API_KEY
- README.md: documents /complete usage

```shellscript
curl -X POST http://localhost:3001/complete \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"
```

---

**User**

how can I update my github repo ?

---

**Cursor**

Here’s the quickest way from your project folder (C:\Users\User\Documents\Cursor\Taller2-3).

If this project is already a git repo (has a .git folder):
1) Stage, commit, push
```powershell
git status
git add -A
git commit -m "Add MongoDB persistence, deanonymize, and OpenAI completion"
git push
```

If remote isn’t set yet (first time push):
- Create an empty repo on GitHub (no README/.gitignore/license), copy its HTTPS URL.
```powershell
git init
git add -A
git commit -m "Initial commit: Data Privacy Vault (anonymize, deanonymize, MongoDB, OpenAI)"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

If you want to use a feature branch and PR:
```powershell
git checkout -b feature/openai-completion
git add -A
git commit -m "Add OpenAI client and /complete endpoint"
git push -u origin feature/openai-completion
```
Then open a PR on GitHub.

Important:
- Your .gitignore excludes .env; don’t commit secrets. Keep your real OPENAI_API_KEY and MONGODB_URI only in .env.
- If Git asks for credentials, use a GitHub Personal Access Token (fine-grained/classic) as the password when prompted.

Troubleshooting:
- Update remote URL: git remote set-url origin https://github.com/<user>/<repo>.git
- See remotes: git remote -v
- Rename default branch if needed: git branch -M main

```powershell
git status
git add -A
git commit -m "Add MongoDB persistence, deanonymize, and OpenAI completion"
git push
```

```powershell
git init
git add -A
git commit -m "Initial commit: Data Privacy Vault (anonymize, deanonymize, MongoDB, OpenAI)"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

```powershell
git checkout -b feature/openai-completion
git add -A
git commit -m "Add OpenAI client and /complete endpoint"
git push -u origin feature/openai-completion
```

---

**User**

there is no a git folder, but a gitignore file,... 

---

**Cursor**

You just need to initialize a repo and push it to GitHub.

Steps (PowerShell, in your project folder):
1) Initialize and commit
- cd "C:\Users\User\Documents\Cursor\Taller2-3"
- git init
- git add -A
- git commit -m "Initial commit: Data Privacy Vault (MongoDB + OpenAI)"

2) Set main branch and remote
- git branch -M main
- Create an empty repo on GitHub (no README/.gitignore), copy its HTTPS URL
- git remote add origin https://github.com/<your-username>/<your-repo>.git

3) Push
- git push -u origin main

Optional setup (first time git on this machine):
- git config --global user.name "Your Name"
- git config --global user.email "you@example.com"

Notes
- Your .gitignore already ignores .env; keep secrets only in .env (don’t commit it).
- When prompted for credentials, use a GitHub Personal Access Token as the password.

---

**User**

I git this when execute git init command:


---

**Cursor**

git no está instalado o no está en tu PATH. Instálalo y vuelve a intentar.

Opciones para instalar en Windows:

- Instalador oficial (recomendado)
  1) Descarga e instala desde: https://git-scm.com/download/win
  2) Acepta “Add Git to PATH” durante la instalación.
  3) Cierra y abre una nueva PowerShell.
  4) Verifica: git --version

- Con winget (si lo tienes)
  - winget install --id Git.Git -e --source winget

- Con Chocolatey (si lo tienes)
  - choco install git -y

Después de instalar:
1) Nueva PowerShell
2) Ve a tu proyecto:
   - cd "C:\Users\User\Documents\Cursor\Taller2-3"
3) Inicializa y sube:
   - git init
   - git add -A
   - git commit -m "Initial commit: Data Privacy Vault (MongoDB + OpenAI)"
   - git branch -M main
   - git remote add origin https://github.com/<tu-usuario>/<tu-repo>.git
   - git push -u origin main

Si git sigue sin reconocerse:
- Revisa PATH: $env:Path
- Asegúrate de que exista algo como C:\Program Files\Git\cmd
- Si no, reinstala Git marcando “Add to PATH” y abre una nueva terminal.

---

**User**

I have updated the .env file with my openAI api key, executed the command npm install, started the Application, but when I tested with the command suggested I got this message:
{"error":"Not Found","details":"The requested endpoint does not exist"}

---

**Cursor**

Likely you’re hitting the wrong method/path or quoting is off in PowerShell. Quick checks:

- Confirm server logs show these lines on startup:
  - “💬 Completion endpoint: POST http://localhost:3001/complete”
  - “🤖 OpenAI client initialized”
  If not, restart the app after saving .env.

- Use POST, not GET. Use correct port (3001). Use proper JSON quoting for PowerShell.

Working commands for PowerShell:
- Using curl with escaped JSON:
```powershell
curl -X POST http://localhost:3001/complete `
  -H "Content-Type: application/json" `
  -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"
```
- Or using Invoke-WebRequest (often easier on Windows):
```powershell
Invoke-WebRequest -Method POST -Uri http://localhost:3001/complete `
  -Headers @{ "Content-Type" = "application/json" } `
  -Body '{"prompt":"Write a short, friendly greeting in Spanish"}' | Select-Object -Expand Content
```

If you still get Not Found:
- Verify the endpoint exists in your running server (you should see “💬 Completion endpoint” in logs).
- Ensure you’re not on a different port (check the “running on port …” log).
- Remove trailing slash (use /complete, not /complete/).
- Ensure it’s POST (GET /complete returns 404).
- Make sure .env is in the project root and OPENAI_API_KEY is set, then fully restart the server.

```powershell
curl -X POST http://localhost:3001/complete `
  -H "Content-Type: application/json" `
  -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"
```

```powershell
Invoke-WebRequest -Method POST -Uri http://localhost:3001/complete `
  -Headers @{ "Content-Type" = "application/json" } `
  -Body '{"prompt":"Write a short, friendly greeting in Spanish"}' | Select-Object -Expand Content
```

---

**User**

I am using cmd terminal,. not powershell terminal.
I set OPENAI_API_KEY in .env file.
I restarted the application.
When the app started, I show that the complete endpoint exists:
 Completion endpoint: POST http://localhost:3001/complete
But, when I tested, I got:  {"error":"Not Found","details":"The requested endpoint does not exist"}

---

**Cursor**

```shellscript
curl -X POST http://localhost:3001/complete -H "Content-Type: application/json" -d "{\"prompt\":\"Write a short greeting in Spanish\"}"
```

- You’re on cmd.exe, so use double quotes and escape inner quotes. Also ensure it’s POST to /complete exactly (no trailing slash) on port 3001.

Try these checks in cmd.exe:
1) Verify server and port
- curl http://localhost:3001/health
  Should return JSON with status healthy.

2) Call the endpoint (cmd.exe quoting):
```cmd
curl -X POST http://localhost:3001/complete -H "Content-Type: application/json" -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"
```

If you still get 404:
- Use 127.0.0.1 instead of localhost:
```cmd
curl -X POST http://127.0.0.1:3001/complete -H "Content-Type: application/json" -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"
```
- Ensure there’s no trailing slash: use /complete not /complete/
- Confirm it’s POST (GET /complete will 404)
- Confirm the app printed “Completion endpoint: POST http://localhost:3001/complete” at startup

If it’s not 404 but 501:
- That means OPENAI_API_KEY wasn’t loaded; ensure .env is in the project root and restart the app.

```plaintext
curl -X POST http://localhost:3001/complete -H "Content-Type: application/json" -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"
```

```plaintext
curl -X POST http://127.0.0.1:3001/complete -H "Content-Type: application/json" -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"
```

---

**User**

All the steps are set and correct. The health endpoint returns: 
{"status":"healthy","service":"Data Privacy Vault","version":"1.0.0","timestamp":"2025-10-30T03:02:33.527Z"}


---

**Cursor**

I'll fix the 404 by registering the /complete route before the 404 middleware and hoisting the OpenAI client variable so the route can access it. Then I'll remove the duplicate route definition inside the startup block.

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Disable mongoose buffering so ops fail fast when disconnected instead of timing out
mongoose.set('bufferCommands', false);

const Token = require('./models/Token');
const OpenAIClient = require('./services/OpenAIClient');

// Hoisted OpenAI client instance (initialized at startup)
let openAI;

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    if (mongoose.connection.readyState !== 1) {
      return;
    }
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Helper to check if DB is connected
 */
function isDbConnected() {
  return mongoose.connection.readyState === 1; // 1 = connected
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  if (isDbConnected()) {
    try {
      const existingDoc = await Token.findByOriginalValue(normalizedValue);
      
      if (existingDoc) {
        // Token exists in database - load into cache
        const token = existingDoc.token;
        const docType = existingDoc.type;
        
        // Populate caches
        tokenCache.set(normalizedValue, token);
        reverseTokenCache.set(token, { value: normalizedValue, type: docType });
        
        return `${docType}_${token}`;
      }
    } catch (error) {
      console.error('Error checking MongoDB for existing token:', error.message);
      // Continue to generate new token
    }
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence (if connected)
  if (isDbConnected()) {
    try {
      const newToken = new Token({
        originalValue: normalizedValue,
        token: token,
        type: type
      });
      
      await newToken.save();
      console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
      
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error - token already exists (race condition)
        console.warn(`Token ${token} already exists in database`);
      } else {
        console.error('Error saving token to MongoDB:', error.message);
      }
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB (only if connected)
    if (!originalData && isDbConnected()) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server and connect to database
(async () => {
  // Connect to MongoDB Atlas
  await connectDatabase();
  
  // Initialize OpenAI only if key is present
  let openAI;
  try {
    if (process.env.OPENAI_API_KEY) {
      openAI = new OpenAIClient({});
      console.log('🤖 OpenAI client initialized');
    } else {
      console.warn('⚠️  OPENAI_API_KEY not set. /complete endpoint will return 501.');
    }
  } catch (e) {
    console.error('Failed to initialize OpenAI client:', e.message);
  }

  // POST /complete - text completion via OpenAI
  app.post('/complete', async (req, res) => {
    try {
      if (!openAI) {
        return res.status(501).json({
          error: 'Not Implemented',
          details: 'OpenAI is not configured on this server'
        });
      }

      const { prompt, model, temperature, maxTokens } = req.body || {};
      if (!prompt || typeof prompt !== 'string') {
        return res.status(400).json({
          error: 'Bad Request',
          details: 'prompt (string) is required'
        });
      }

      const text = await openAI.completeText(prompt, { model, temperature, maxTokens });
      return res.json({ completion: text });
    } catch (error) {
      console.error('Error in /complete endpoint:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        details: 'Failed to generate completion'
      });
    }
  });

  // Start the Express server
  app.listen(PORT, () => {
    console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
    console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
    console.log(`💬 Completion endpoint: POST http://localhost:${PORT}/complete`);
    console.log(`📈 Stats endpoint: GET http://localhost:${PORT}/stats`);
  });
})();

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Disable mongoose buffering so ops fail fast when disconnected instead of timing out
mongoose.set('bufferCommands', false);

const Token = require('./models/Token');
const OpenAIClient = require('./services/OpenAIClient');

// Hoisted OpenAI client instance (initialized at startup)
let openAI;

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    if (mongoose.connection.readyState !== 1) {
      return;
    }
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Helper to check if DB is connected
 */
function isDbConnected() {
  return mongoose.connection.readyState === 1; // 1 = connected
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  if (isDbConnected()) {
    try {
      const existingDoc = await Token.findByOriginalValue(normalizedValue);
      
      if (existingDoc) {
        // Token exists in database - load into cache
        const token = existingDoc.token;
        const docType = existingDoc.type;
        
        // Populate caches
        tokenCache.set(normalizedValue, token);
        reverseTokenCache.set(token, { value: normalizedValue, type: docType });
        
        return `${docType}_${token}`;
      }
    } catch (error) {
      console.error('Error checking MongoDB for existing token:', error.message);
      // Continue to generate new token
    }
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence (if connected)
  if (isDbConnected()) {
    try {
      const newToken = new Token({
        originalValue: normalizedValue,
        token: token,
        type: type
      });
      
      await newToken.save();
      console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
      
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error - token already exists (race condition)
        console.warn(`Token ${token} already exists in database`);
      } else {
        console.error('Error saving token to MongoDB:', error.message);
      }
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB (only if connected)
    if (!originalData && isDbConnected()) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// POST /complete - text completion via OpenAI
app.post('/complete', async (req, res) => {
  try {
    if (!openAI) {
      return res.status(501).json({
        error: 'Not Implemented',
        details: 'OpenAI is not configured on this server'
      });
    }

    const { prompt, model, temperature, maxTokens } = req.body || {};
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'prompt (string) is required'
      });
    }

    const text = await openAI.completeText(prompt, { model, temperature, maxTokens });
    return res.json({ completion: text });
  } catch (error) {
    console.error('Error in /complete endpoint:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      details: 'Failed to generate completion'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server and connect to database
(async () => {
  // Connect to MongoDB Atlas
  await connectDatabase();
  
  // Initialize OpenAI only if key is present
  let openAI;
  try {
    if (process.env.OPENAI_API_KEY) {
      openAI = new OpenAIClient({});
      console.log('🤖 OpenAI client initialized');
    } else {
      console.warn('⚠️  OPENAI_API_KEY not set. /complete endpoint will return 501.');
    }
  } catch (e) {
    console.error('Failed to initialize OpenAI client:', e.message);
  }

  // POST /complete - text completion via OpenAI
  app.post('/complete', async (req, res) => {
    try {
      if (!openAI) {
        return res.status(501).json({
          error: 'Not Implemented',
          details: 'OpenAI is not configured on this server'
        });
      }

      const { prompt, model, temperature, maxTokens } = req.body || {};
      if (!prompt || typeof prompt !== 'string') {
        return res.status(400).json({
          error: 'Bad Request',
          details: 'prompt (string) is required'
        });
      }

      const text = await openAI.completeText(prompt, { model, temperature, maxTokens });
      return res.json({ completion: text });
    } catch (error) {
      console.error('Error in /complete endpoint:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        details: 'Failed to generate completion'
      });
    }
  });

  // Start the Express server
  app.listen(PORT, () => {
    console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
    console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
    console.log(`💬 Completion endpoint: POST http://localhost:${PORT}/complete`);
    console.log(`📈 Stats endpoint: GET http://localhost:${PORT}/stats`);
  });
})();

module.exports = app;


```

```javascript
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Disable mongoose buffering so ops fail fast when disconnected instead of timing out
mongoose.set('bufferCommands', false);

const Token = require('./models/Token');
const OpenAIClient = require('./services/OpenAIClient');

// Hoisted OpenAI client instance (initialized at startup)
let openAI;

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

/**
 * PII Anonymization Service
 * This service detects and anonymizes Personally Identifiable Information (PII)
 * including names, emails, and phone numbers using consistent tokenization.
 */

/**
 * Token cache to ensure consistent tokenization (in-memory fallback)
 * Same PII value will always generate the same token
 * Map: original_value -> token
 * Note: This is now a fallback cache for performance optimization
 */
const tokenCache = new Map();

/**
 * Reverse token cache for deanonymization (in-memory fallback)
 * Map: token -> { value: original_value, type: PII_type }
 * Note: This is now a fallback cache for performance optimization
 */
const reverseTokenCache = new Map();

/**
 * Connect to MongoDB Atlas
 * This function establishes the database connection
 */
async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.warn('⚠️  Warning: MONGODB_URI not set. Running in in-memory mode only.');
      console.warn('⚠️  Tokens will not persist across server restarts.');
      return;
    }
    
    const conn = await mongoose.connect(mongoUri, {
      // Connection options for better reliability
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });
    
    console.log(`✅ MongoDB Atlas connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Load existing tokens into cache on startup
    await loadTokensIntoCache();
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('⚠️  Continuing in in-memory mode. Tokens will not persist.');
  }
}

/**
 * Load existing tokens from MongoDB into in-memory cache for faster access
 * This improves performance by reducing database queries
 */
async function loadTokensIntoCache() {
  try {
    if (mongoose.connection.readyState !== 1) {
      return;
    }
    const tokens = await Token.find({});
    
    for (const tokenDoc of tokens) {
      // Populate forward cache (original value -> token)
      tokenCache.set(tokenDoc.originalValue, tokenDoc.token);
      
      // Populate reverse cache (token -> original data)
      reverseTokenCache.set(tokenDoc.token, {
        value: tokenDoc.originalValue,
        type: tokenDoc.type
      });
    }
    
    console.log(`📦 Loaded ${tokens.length} tokens into memory cache`);
    
  } catch (error) {
    console.error('Error loading tokens into cache:', error.message);
  }
}

/**
 * Helper to check if DB is connected
 */
function isDbConnected() {
  return mongoose.connection.readyState === 1; // 1 = connected
}

/**
 * Generates a consistent 8-character alphanumeric token for a given value
 * Saves the token to MongoDB for persistence
 * @param {string} value - The original PII value to tokenize
 * @param {string} type - The type of PII ('NAME', 'EMAIL', 'PHONE')
 * @returns {Promise<string>} - Formatted token with type prefix (e.g., 'EMAIL_a1b2c3d4')
 */
async function generateToken(value, type) {
  const normalizedValue = value.toLowerCase();
  
  // Check if we already have a token in cache
  if (tokenCache.has(normalizedValue)) {
    const existingToken = tokenCache.get(normalizedValue);
    const existingType = reverseTokenCache.get(existingToken)?.type;
    
    // If token exists but has different type, that's an error condition
    if (existingType !== type) {
      console.warn(`Warning: Value '${value}' already tokenized as ${existingType}, but requested as ${type}`);
    }
    
    return `${existingType}_${existingToken}`;
  }

  // Check MongoDB for existing token
  if (isDbConnected()) {
    try {
      const existingDoc = await Token.findByOriginalValue(normalizedValue);
      
      if (existingDoc) {
        // Token exists in database - load into cache
        const token = existingDoc.token;
        const docType = existingDoc.type;
        
        // Populate caches
        tokenCache.set(normalizedValue, token);
        reverseTokenCache.set(token, { value: normalizedValue, type: docType });
        
        return `${docType}_${token}`;
      }
    } catch (error) {
      console.error('Error checking MongoDB for existing token:', error.message);
      // Continue to generate new token
    }
  }

  // Generate a new consistent hash-based token
  const hash = crypto.createHash('sha256').update(normalizedValue).digest('hex');
  const token = hash.substring(0, 8); // Take first 8 characters
  const formattedToken = `${type}_${token}`;
  
  // Store in memory caches
  tokenCache.set(normalizedValue, token);
  reverseTokenCache.set(token, { value: normalizedValue, type: type });
  
  // Save to MongoDB for persistence (if connected)
  if (isDbConnected()) {
    try {
      const newToken = new Token({
        originalValue: normalizedValue,
        token: token,
        type: type
      });
      
      await newToken.save();
      console.log(`💾 Saved new token to MongoDB: ${type}_${token}`);
      
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error - token already exists (race condition)
        console.warn(`Token ${token} already exists in database`);
      } else {
        console.error('Error saving token to MongoDB:', error.message);
      }
    }
  }
  
  return formattedToken;
}

/**
 * Removes the PII type prefix from a token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - Plain token without prefix
 */
function extractToken(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null; // Invalid format
  }
  return parts[1]; // Return token part after the prefix
}

/**
 * Gets the PII type from a formatted token
 * @param {string} formattedToken - Token with prefix (e.g., 'EMAIL_a1b2c3d4')
 * @returns {string} - The PII type ('NAME', 'EMAIL', 'PHONE')
 */
function getTokenType(formattedToken) {
  const parts = formattedToken.split('_');
  if (parts.length < 2) {
    return null;
  }
  return parts[0]; // Return type part before the underscore
}

/**
 * Regular expressions for detecting different types of PII
 */
const PII_PATTERNS = {
  // Email pattern: matches standard email formats
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  
  // Phone pattern: matches various phone number formats
  // Supports formats like: 3152319157, +57 315 231 9157, (315) 231-9157, etc.
  phone: /(?:\+?[\d\s\-\(\)]{10,}|\b\d{10,}\b)/g,
  
  // Name pattern: matches capitalized words (potential names)
  // This is a simplified approach - in production, you might want to use NLP or name dictionaries
  name: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g
};

/**
 * Validates if a phone number string is actually a phone number
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a phone number
 */
function isValidPhone(str) {
  // Remove all non-digit characters
  const digits = str.replace(/\D/g, '');
  
  // Check if it has a reasonable number of digits for a phone number
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Validates if a capitalized word is likely a name
 * @param {string} str - The string to validate
 * @returns {boolean} - True if it's likely a name
 */
function isValidName(str) {
  // Basic validation: at least 2 characters, starts with capital
  // In production, you might want to check against common words dictionary
  // to avoid false positives like "Buenos", "De", etc.
  const commonWords = ['Buenos', 'De', 'La', 'El', 'Con', 'Para', 'Sobre', 'Desde', 'Hasta'];
  return str.length >= 2 && !commonWords.includes(str);
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message) {
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  for (const match of nameMatches) {
    if (isValidName(match)) {
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    }
  }

  return anonymized;
}

/**
 * Deanonymizes a message by replacing tokens with original PII values
 * Queries MongoDB if token not found in cache
 * @param {string} anonymizedMessage - The anonymized message with tokens
 * @returns {Promise<string>} - The deanonymized message with original PII values
 */
async function deanonymizeMessage(anonymizedMessage) {
  let deanonymized = anonymizedMessage;
  
  // Pattern to match tokens with type prefix: TYPE_token12345678
  const tokenPattern = /(NAME|EMAIL|PHONE)_[a-f0-9]{8}/g;
  const tokens = anonymizedMessage.match(tokenPattern) || [];
  
  // Replace all tokens with their original values
  for (const match of tokens) {
    const token = extractToken(match);
    
    if (!token) {
      continue; // Skip if token extraction fails
    }
    
    // Check cache first
    let originalData = reverseTokenCache.get(token);
    
    // If not in cache, query MongoDB (only if connected)
    if (!originalData && isDbConnected()) {
      try {
        const tokenDoc = await Token.findByToken(token);
        
        if (tokenDoc) {
          // Store in cache for future use
          originalData = { value: tokenDoc.originalValue, type: tokenDoc.type };
          reverseTokenCache.set(token, originalData);
          
          // Also populate forward cache
          tokenCache.set(tokenDoc.originalValue, token);
          
          // Update usage statistics
          await tokenDoc.incrementUsage();
        }
      } catch (error) {
        console.error('Error querying MongoDB for token:', error.message);
      }
    }
    
    if (originalData) {
      deanonymized = deanonymized.replace(match, originalData.value);
    } else {
      // Token not found - return original token
      console.warn(`Warning: Token ${match} not found in cache or database`);
    }
  }
  
  return deanonymized;
}

/**
 * POST /anonymize
 * Endpoint to anonymize PII in a message
 * 
 * Request body: { "message": "string containing PII" }
 * Response: { "anonymizedMessage": "string with PII replaced by tokens" }
 */
app.post('/anonymize', async (req, res) => {
  try {
    // Validate request body
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message field is required'
      });
    }

    if (typeof message !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'Message must be a string'
      });
    }

    // Anonymize the message (async operation)
    const anonymizedMessage = await anonymizeMessage(message);

    // Return the result
    res.json({
      anonymizedMessage: anonymizedMessage
    });

  } catch (error) {
    console.error('Error in /anonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Data Privacy Vault',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /deanonymize
 * Endpoint to deanonymize a message (convert tokens back to original PII)
 * 
 * Request body: { "anonymizedMessage": "string with tokens" }
 * Response: { "message": "string with original PII values" }
 */
app.post('/deanonymize', async (req, res) => {
  try {
    // Validate request body
    const { anonymizedMessage } = req.body;

    if (!anonymizedMessage) {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage field is required'
      });
    }

    if (typeof anonymizedMessage !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'anonymizedMessage must be a string'
      });
    }

    // Deanonymize the message (async operation)
    const message = await deanonymizeMessage(anonymizedMessage);

    // Return the result
    res.json({
      message: message
    });

  } catch (error) {
    console.error('Error in /deanonymize endpoint:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      details: 'An error occurred while processing the request'
    });
  }
});

/**
 * GET /stats
 * Returns anonymization statistics
 */
app.get('/stats', async (req, res) => {
  try {
    let totalTokensInDB = 0;
    
    // Get count from MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      totalTokensInDB = await Token.countDocuments();
    }
    
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      totalTokensInDatabase: totalTokensInDB,
      service: 'Data Privacy Vault',
      databaseConnected: mongoose.connection.readyState === 1
    });
  } catch (error) {
    res.json({
      totalTokensInMemory: tokenCache.size,
      totalTokensInReverseCache: reverseTokenCache.size,
      service: 'Data Privacy Vault',
      databaseConnected: false,
      error: 'Could not retrieve database stats'
    });
  }
});

// POST /complete - text completion via OpenAI
app.post('/complete', async (req, res) => {
  try {
    if (!openAI) {
      return res.status(501).json({
        error: 'Not Implemented',
        details: 'OpenAI is not configured on this server'
      });
    }

    const { prompt, model, temperature, maxTokens } = req.body || {};
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({
        error: 'Bad Request',
        details: 'prompt (string) is required'
      });
    }

    const text = await openAI.completeText(prompt, { model, temperature, maxTokens });
    return res.json({ completion: text });
  } catch (error) {
    console.error('Error in /complete endpoint:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      details: 'Failed to generate completion'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    details: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    details: 'The requested endpoint does not exist'
  });
});

// Start server and connect to database
(async () => {
  // Connect to MongoDB Atlas
  await connectDatabase();
  
  // Initialize OpenAI only if key is present
  try {
    if (process.env.OPENAI_API_KEY) {
      openAI = new OpenAIClient({});
      console.log('🤖 OpenAI client initialized');
    } else {
      console.warn('⚠️  OPENAI_API_KEY not set. /complete endpoint will return 501.');
    }
  } catch (e) {
    console.error('Failed to initialize OpenAI client:', e.message);
  }

  // Start the Express server
  app.listen(PORT, () => {
    console.log(`🔒 Data Privacy Vault running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🎯 Anonymize endpoint: POST http://localhost:${PORT}/anonymize`);
    console.log(`🔓 Deanonymize endpoint: POST http://localhost:${PORT}/deanonymize`);
    console.log(`💬 Completion endpoint: POST http://localhost:${PORT}/complete`);
    console.log(`📈 Stats endpoint: GET http://localhost:${PORT}/stats`);
  });
})();

module.exports = app;


```

You’re getting 404 because the /complete route was registered after the global 404 handler. I moved the route definition above the 404 so Express can match it.

What to do now:
- Restart the app
- Test again from cmd.exe:
  - curl -X POST http://localhost:3001/complete -H "Content-Type: application/json" -d "{\"prompt\":\"Write a short, friendly greeting in Spanish\"}"

You should still see the “Completion endpoint: POST http://localhost:3001/complete” line on startup, and the call should return a JSON completion instead of Not Found.

---

**User**

it works !!

---

**Cursor**

Excelente. ¿Quieres que agreguemos algo más ahora?
- Guardar logs de completions
- Límite de rate/requests
- Soporte de modelos y parámetros por usuario
- Streaming de respuestas
- Tests para el endpoint /complete

