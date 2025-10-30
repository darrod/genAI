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

