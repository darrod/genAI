# Data Privacy Vault + Secure ChatGPT

This project provides a Node.js service that anonymizes PII (names, emails, phones) in free text, optionally persists token mappings in MongoDB Atlas, and integrates with OpenAI to safely process prompts. A secure endpoint `/secureChatGPT` anonymizes the user prompt, sends it to OpenAI, then deanonymizes the AI response before returning it.

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

### POST /secureChatGPT

Securely processes prompts that may contain PII.

Flow: anonymize prompt → OpenAI completion → deanonymize response.

Environment: set `OPENAI_API_KEY` in `.env`.

**📝 Important: Name Detection Best Practices**

For **reliable name detection**, especially for lowercase names, use one of these patterns:

**Spanish:**
- ✅ `"cuyo nombre es [Nombre Apellido]"`
- ✅ `"llamado [Nombre Apellido]"` or `"llamada [Nombre Apellido]"`
- ✅ `"de nombre [Nombre Apellido]"`
- ✅ `"nombre: [Nombre Apellido]"`

**English:**
- ✅ `"whose name is [First Last]"`
- ✅ `"called [First Last]"`
- ✅ `"named [First Last]"`
- ✅ `"name: [First Last]"`

**Why?** Emails and phone numbers have clear patterns (`@`, digits), but names can be ambiguous. Using name indicators significantly improves detection reliability.

**Note:** The service supports both Spanish and English prompts. Capitalized names (e.g., "John Smith", "María González") are automatically detected in both languages.

**Examples:**

✅ **Good** - Uses name indicator (works with any name, including accented names):
```bash
curl -X POST http://localhost:3001/secureChatGPT \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Haz un resumen de las habilidades de la persona cuyo nombre es carlos rodríguez. Su email es carlosr@mail.com y su número es 3129876543\"}"
```

✅ **Also Good** - Lowercase name without accents:
```bash
curl -X POST http://localhost:3001/secureChatGPT \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Haz un resumen de las habilidades de la persona cuyo nombre es maria garcia. Su email es maria@email.com y su número es 3001234567\"}"
```

✅ **English Example** - With name indicator:
```bash
curl -X POST http://localhost:3001/secureChatGPT \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Create a summary of skills for the person whose name is john smith. Email: john@email.com, phone: 5551234567\"}"
```

✅ **Good** - Capitalized name (detected automatically in Spanish or English):
```bash
curl -X POST http://localhost:3001/secureChatGPT \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Resume el CV de Juan Pérez con email juan@email.com y teléfono 3152319157\"}"
```

✅ **Also Good** - Uses "llamado" indicator (works with any name):
```bash
curl -X POST http://localhost:3001/secureChatGPT \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Analiza el perfil de la persona llamada Ana López. Contacto: ana@email.com, tel: 3001234567\"}"
```

**Request:**
```bash
curl -X POST http://localhost:3001/secureChatGPT \
  -H "Content-Type: application/json" \
  -d "{\"prompt\":\"Your prompt here\"}"
```

Optional JSON fields: `model`, `temperature`, `maxTokens`.

**Response:**
```json
{
  "answer": "..."
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
- **Capitalized names**: Automatically detected in both Spanish and English
  - Spanish examples: "Juan Pérez", "María González", "Carlos Rodríguez"
  - English examples: "John Smith", "Jane Doe", "Robert Johnson"
- **Lowercase names**: Best detected when preceded by name indicators:
  - **Spanish**: `"cuyo nombre es [nombre]"`, `"llamado [nombre]"`, `"de nombre [nombre]"`, `"nombre: [nombre]"`
  - **English**: `"whose name is [name]"`, `"called [name]"`, `"named [name]"`, `"name: [name]"`
- **Multi-language support**: The system supports both Spanish and English prompts
- **Accented characters**: Fully supported (e.g., "Rodríguez", "María", "José")
  - Accents and special characters are preserved correctly
  - Names are normalized to lowercase for storage, but original formatting is preserved
- Basic validation to reduce false positives (includes Spanish and English stopwords)
- Pattern: `Firstname Lastname` (at least 3 characters each word)
- **Recommendation**: Always use name indicators for lowercase names to ensure reliable detection
- **Note**: The system handles Spanish characters (á, é, í, ó, ú, ñ) correctly in both detection and storage

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
