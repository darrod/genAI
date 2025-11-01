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
    
    console.log(`📦 Using cached token for ${type}: ${normalizedValue} -> ${existingType}_${existingToken}`);
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
        
        console.log(`💾 Found existing token in MongoDB for ${type}: ${normalizedValue} -> ${docType}_${token}`);
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
  
  console.log(`🆕 Generating new token for ${type}: ${normalizedValue} -> ${formattedToken}`);
  
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
      console.log(`💾 ✅ Saved NEW token to MongoDB: ${type}_${token}`);
      console.log(`   Value saved: "${normalizedValue}" (${normalizedValue.length} chars, ${Buffer.from(normalizedValue).length} bytes)`);
      
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error - token already exists (race condition)
        console.warn(`⚠️ Token ${token} already exists in database (race condition)`);
      } else {
        console.error('❌ Error saving token to MongoDB:', error.message);
        console.error('Error details:', error);
      }
    }
  } else {
    console.warn(`⚠️ MongoDB not connected. Token ${formattedToken} stored in memory only.`);
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
  const commonWords = [
    // Spanish - Articles and determiners
    'De', 'Del', 'La', 'El', 'Los', 'Las', 'Un', 'Una', 'Unos', 'Unas',
    // Spanish - Possessive determiners
    'Su', 'Sus', 'Mi', 'Mis', 'Tu', 'Tus', 'Nuestro', 'Nuestra', 'Nuestros', 'Nuestras',
    // Spanish - Prepositions
    'Con', 'Para', 'Sobre', 'Desde', 'Hasta', 'Por', 'En', 'A', 'Al',
    // Spanish - Common capitalized words
    'Buenos', 'Este', 'Esta', 'Estos', 'Estas', 'Ese', 'Esa', 'Esos', 'Esas',
    // Spanish - Common verbs that start with capital (when at start of sentence)
    'Es', 'Son', 'Era', 'Fue', 'Ha', 'Han', 'Resume', 'Resumen', 'Haz', 'Hace',
    'Crea', 'Crear', 'Genera', 'Generar', 'Escribe', 'Escribir', 'Analiza', 'Analizar',
    // English - Articles and determiners
    'The', 'A', 'An', 'Some', 'Any',
    // English - Possessive determiners
    'His', 'Her', 'Their', 'Our', 'Your', 'My', 'Its',
    // English - Common verbs that start with capital (when at start of sentence)
    'Is', 'Are', 'Was', 'Were', 'Has', 'Have', 'Write', 'Writes', 'Create', 'Creates',
    'Generate', 'Generates', 'Analyze', 'Analyzes', 'Summary', 'Resume', 'Contact', 'Contacts'
  ];
  
  // Reject if it's a common word
  if (commonWords.includes(str)) {
    return false;
  }
  
  // Reject if too short (less than 3 characters) - prevents "Su", "Mi", "Tu", etc.
  if (str.length < 3) {
    return false;
  }
  
  return true;
}

/**
 * Anonymizes PII in the given message
 * @param {string} message - The original message containing PII
 * @returns {Promise<string>} - The anonymized message with tokens replacing PII
 */
async function anonymizeMessage(message, options = {}) {
  const { lenientNames = false } = options;
  let anonymized = message;

  // Step 1: Anonymize emails
  const emailMatches = message.match(PII_PATTERNS.email) || [];
  console.log(`📧 Found ${emailMatches.length} email(s) to anonymize:`, emailMatches);
  for (const match of emailMatches) {
    const token = await generateToken(match, 'EMAIL');
    anonymized = anonymized.replace(match, token);
  }

  // Step 2: Anonymize phone numbers
  const phoneMatches = message.match(PII_PATTERNS.phone) || [];
  console.log(`📱 Found ${phoneMatches.length} phone number(s) to validate:`, phoneMatches);
  for (const match of phoneMatches) {
    if (isValidPhone(match)) {
      console.log(`✅ Valid phone number: ${match}`);
      const token = await generateToken(match, 'PHONE');
      anonymized = anonymized.replace(match, token);
    } else {
      console.log(`❌ Invalid phone number (filtered): ${match}`);
    }
  }

  // Step 3: Anonymize names (be careful with false positives)
  const nameMatches = message.match(PII_PATTERNS.name) || [];
  console.log(`👤 Found ${nameMatches.length} capitalized name(s) to validate:`, nameMatches);
  for (const match of nameMatches) {
    if (isValidName(match)) {
      console.log(`✅ Valid capitalized name: ${match}`);
      const token = await generateToken(match, 'NAME');
      anonymized = anonymized.replace(match, token);
    } else {
      console.log(`❌ Invalid capitalized name (filtered): ${match}`);
    }
  }

  // Optional lenient mode for names: capture lowercase two-word sequences likely to be names
  if (lenientNames) {
    console.log(`\n🔍 Starting lenient name detection mode...`);
    console.log(`📝 Current anonymized text: "${anonymized}"`);
    
    // Step 3.5: Detect names after specific name indicators (more reliable)
    // Spanish patterns: "cuyo nombre es", "llamado", "de nombre", "nombre:"
    // English patterns: "whose name is", "called", "named", "name:"
    const nameIndicators = [
      // Spanish indicators - capitalized
      /\bcuyo\s+nombre\s+es\s+([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+)+)/gi,
      /\bllamad[ao]\s+([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+)+)/gi,
      /\bde\s+nombre\s+([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+)+)/gi,
      /\bnombre[:\s]+([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+)+)/gi,
      // Spanish indicators - lowercase
      /\bcuyo\s+nombre\s+es\s+([a-záéíóúñ]{3,}\s+[a-záéíóúñ]{3,})/gi,
      /\bllamad[ao]\s+([a-záéíóúñ]{3,}\s+[a-záéíóúñ]{3,})/gi,
      /\bde\s+nombre\s+([a-záéíóúñ]{3,}\s+[a-záéíóúñ]{3,})/gi,
      // English indicators - capitalized
      /\bwhose\s+name\s+is\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/gi,
      /\bcalled\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/gi,
      /\bnamed\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/gi,
      /\bname[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/gi,
      // English indicators - lowercase
      /\bwhose\s+name\s+is\s+([a-z]{3,}\s+[a-z]{3,})/gi,
      /\bcalled\s+([a-z]{3,}\s+[a-z]{3,})/gi,
      /\bnamed\s+([a-z]{3,}\s+[a-z]{3,})/gi,
      /\bname[:\s]+([a-z]{3,}\s+[a-z]{3,})/gi
    ];
    
    // Store original names with their exact text to preserve accents
    const indicatorMatches = [];
    const seenNames = new Set();
    
    for (const pattern of nameIndicators) {
      let m;
      pattern.lastIndex = 0;
      while ((m = pattern.exec(anonymized)) !== null) {
        const nameCandidate = m[1];  // This is the actual name with original case and accents
        // Validate it's not already a token and has minimum length
        if (!nameCandidate.includes('_') && nameCandidate.length > 5) {
          const normalizedKey = nameCandidate.toLowerCase();
          // Avoid duplicates (same name in different cases)
          if (!seenNames.has(normalizedKey)) {
            seenNames.add(normalizedKey);
            indicatorMatches.push({
              originalName: nameCandidate,  // Keep original with accents and case intact
              index: m.index
            });
            console.log(`🎯 Found name after indicator: "${nameCandidate}" (length: ${nameCandidate.length}) at position ${m.index}`);
          }
        }
      }
    }
    
    // Process indicator-based names first (they're more reliable)
    // Sort by position (end to start) to avoid interference when replacing
    indicatorMatches.sort((a, b) => b.index - a.index);
    
    for (const match of indicatorMatches) {
      const originalName = match.originalName;
      
      // Check if name still exists in text (not already replaced with a token)
      const nameRegex = new RegExp(originalName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      if (nameRegex.test(anonymized)) {
        console.log(`✅ Processing indicator-based name: "${originalName}" (preserving accents and case)`);
        console.log(`   Name length: ${originalName.length} characters`);
        console.log(`   Name bytes: ${Buffer.from(originalName).length} bytes`);
        console.log(`   Name normalized (lowercase): "${originalName.toLowerCase()}"`);
        console.log(`   Normalized length: ${originalName.toLowerCase().length} characters`);
        
        // Normalize to lowercase only when saving to DB, but keep original for replacement
        const normalizedForDB = originalName.toLowerCase();
        console.log(`   Saving to DB: "${normalizedForDB}" (${normalizedForDB.length} chars)`);
        
        const token = await generateToken(normalizedForDB, 'NAME');
        const escapedName = originalName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        anonymized = anonymized.replace(new RegExp(escapedName, 'gi'), token);
        console.log(`   Replaced "${originalName}" (${originalName.length} chars) with ${token}`);
      } else {
        console.log(`⏭️ Skipping "${originalName}" - already processed or not found`);
      }
    }
    
    // Comprehensive stopwords (Spanish and English) to avoid false positives
    const stopwords = new Set([
      // Spanish - Articles and determiners
      'de', 'del', 'la', 'el', 'los', 'las', 'un', 'una', 'unos', 'unas',
      // Spanish - Possessive determiners
      'su', 'sus', 'mi', 'mis', 'tu', 'tus', 'nuestro', 'nuestra', 'nuestros', 'nuestras',
      'vuestro', 'vuestra', 'vuestros', 'vuestras',
      // Spanish - Prepositions
      'y', 'para', 'con', 'sin', 'sobre', 'desde', 'hasta', 'por', 'en', 'a', 'al',
      // Spanish - Common words
      'oferta', 'trabajo', 'email', 'correo', 'telefono', 'teléfono', 'cv', 'resume', 'resumen',
      'numero', 'número', 'numeros', 'números', 'celular', 'cel', 'contacto', 'contactos',
      'habilidades', 'habilidad', 'es', 'son', 'esta', 'está', 'estan', 'están',
      'haz', 'hace', 'crea', 'crear', 'genera', 'generar', 'escribe', 'escribir',
      'analiza', 'analizar', 'coordina', 'coordinar', 'cuyo', 'cuya', 'cuyos', 'cuyas',
      'nombre', 'nomnbre', 'nom', 'que', 'cual', 'cuales',
      // English - Articles and determiners
      'the', 'a', 'an', 'some', 'any',
      // English - Possessive determiners
      'his', 'her', 'their', 'our', 'your', 'my', 'its',
      // English - Prepositions and conjunctions
      'and', 'or', 'but', 'with', 'from', 'for', 'to', 'in', 'on', 'at', 'by',
      // English - Common words
      'email', 'phone', 'number', 'contact', 'skills', 'skill', 'ability', 'abilities',
      'write', 'writes', 'create', 'creates', 'generate', 'generates', 'analyze', 'analyzes',
      'resume', 'summary', 'summary', 'contact', 'contacts', 'whose', 'called', 'named'
    ]);
    
    // Additional validation: common verbs/pronouns that shouldn't start a name (Spanish and English)
    const invalidFirstWords = new Set([
      // Spanish
      'es', 'son', 'era', 'fue', 'ha', 'han', 'ser', 'estar',
      // English
      'is', 'are', 'was', 'were', 'has', 'have', 'been', 'being'
    ]);
    
    // Use anonymized text for matching (after emails and phones are already tokenized)
    // Support both Spanish and English characters
    const lowerSeqRegex = /\b([a-záéíóúñ]{2,})\s+([a-záéíóúñ]{2,})\b/gi;
    const candidates = [];
    const seen = new Set();
    
    // First, collect all matches from the anonymized text
    let m;
    const matches = [];
    // Collect all matches first
    lowerSeqRegex.lastIndex = 0;
    console.log(`🔎 Searching for name patterns in text: "${anonymized}"`);
    while ((m = lowerSeqRegex.exec(anonymized)) !== null) {
      matches.push({
        candidate: `${m[1]} ${m[2]}`,
        w1: m[1],
        w2: m[2],
        index: m.index
      });
    }
    console.log(`📋 Found ${matches.length} potential name sequences before filtering:`, matches.map(m => `"${m.candidate}"`));
    
    // Process matches and validate
    for (const match of matches) {
      const { candidate, w1, w2 } = match;
      
      // STRICT Primary filter: Skip if any word is a stopword (check both lowercase and as-is)
      const w1Lower = w1.toLowerCase();
      const w2Lower = w2.toLowerCase();
      if (stopwords.has(w1Lower) || stopwords.has(w2Lower) || stopwords.has(w1) || stopwords.has(w2)) {
        console.log(`🚫 Filtered out (stopword): "${candidate}" (w1: "${w1}", w2: "${w2}")`);
        continue;
      }
      
      // STRICT Secondary filter: Skip if first word is a common verb/pronoun (not likely to start a name)
      if (invalidFirstWords.has(w1Lower) || invalidFirstWords.has(w1)) {
        console.log(`🚫 Filtered out (invalid first word): "${candidate}"`);
        continue;
      }
      
      // STRICT Tertiary filter: Skip if either word is too short (less than 3 characters)
      // This is critical - names in Spanish are typically at least 3 characters
      // Prevents false positives like "su", "mi", "tu", "la", "el", etc.
      if (w1.length < 3 || w2.length < 3) {
        console.log(`🚫 Filtered out (too short): "${candidate}" (w1 length: ${w1.length}, w2 length: ${w2.length})`);
        continue;
      }
      
      // Skip if we've already processed this candidate
      if (seen.has(candidate)) {
        console.log(`⏭️ Skipping duplicate candidate: "${candidate}"`);
        continue;
      }
      
      console.log(`✅ Candidate PASSED all filters: "${candidate}"`);
      seen.add(candidate);
      candidates.push(candidate);
    }
    
    // Then, process each candidate and replace
    console.log(`🔍 Found ${candidates.length} name candidates in lenient mode:`, candidates);
    
    for (const candidate of candidates) {
      // Only replace if candidate still exists in anonymized text (not already replaced)
      if (anonymized.includes(candidate)) {
        console.log(`✅ Processing name candidate: "${candidate}"`);
        const token = await generateToken(candidate, 'NAME');
        // Escape special regex characters in candidate for safe replacement
        const escapedCandidate = candidate.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        anonymized = anonymized.replace(new RegExp(escapedCandidate, 'g'), token);
        console.log(`   Replaced all occurrences of "${candidate}" with ${token}`);
      } else {
        console.log(`⏭️ Skipping candidate "${candidate}" - already replaced in text`);
      }
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

/**
 * POST /secureChatGPT
 * 1) Receives { prompt }
 * 2) Anonymizes PII in prompt
 * 3) Sends anonymized prompt to OpenAI
 * 4) Deanonymizes OpenAI response
 * 5) Returns final answer
 * 
 * IMPORTANT - Name Detection Guidelines:
 * For best name detection, use one of these patterns in your prompt:
 * 
 * Spanish:
 * - "cuyo nombre es [Nombre Apellido]"
 * - "llamado [Nombre Apellido]"
 * - "de nombre [Nombre Apellido]"
 * - "nombre: [Nombre Apellido]"
 * 
 * English:
 * - "whose name is [First Last]"
 * - "called [First Last]"
 * - "named [First Last]"
 * - "name: [First Last]"
 * 
 * Examples:
 * ✅ Spanish: "Haz un resumen de las habilidades de la persona cuyo nombre es [nombre apellido]..."
 * ✅ English: "Create a summary for the person whose name is [first last]..."
 * ✅ Capitalized names are detected automatically in both languages: "John Smith", "María González"
 * 
 * Names in capital letters are detected automatically in both Spanish and English, but using
 * name indicators significantly improves detection reliability for lowercase names.
 */
app.post('/secureChatGPT', async (req, res) => {
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

    // 2) Anonymize incoming prompt (lenient names enabled for lowercase cases)
    // The lenient mode includes detection of names after specific indicators
    // like "cuyo nombre es", "llamado", "de nombre", etc.
    const anonymizedPrompt = await anonymizeMessage(prompt, { lenientNames: true });

    // 3) Send to OpenAI
    const aiResponse = await openAI.completeText(anonymizedPrompt, { model, temperature, maxTokens });

    // 4) Deanonymize the response
    const finalAnswer = await deanonymizeMessage(aiResponse);

    // 5) Return the final answer
    return res.json({
      answer: finalAnswer
    });
  } catch (error) {
    console.error('Error in /secureChatGPT endpoint:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      details: 'Failed to process secureChatGPT request'
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

