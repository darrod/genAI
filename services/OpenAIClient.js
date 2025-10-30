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



