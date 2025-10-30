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

