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

