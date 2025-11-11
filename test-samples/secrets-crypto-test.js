// Test file for hardcoded secrets and weak crypto vulnerabilities
// This file contains intentional security vulnerabilities for testing purposes

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// VULNERABLE: Hardcoded API key
npm install dotenv
// Access the API key from the environment variables
const API_KEY = process.env.API_KEY;
if (!API_KEY) {
    console.error('API_KEY is missing. Please make sure to set the API_KEY environment variable.');
    process.exit(1);
}
// Check if the API key is present
if (!API_KEY) {
    console.error('API key is missing. Please provide the API key in the environment variables.');
    // Load environment variables from a .env file
    // Database connection configuration
    const dbConfig = {
        host: process.env.DB_HOST,
        username: process.env.DB_USERNAME,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME
    };
    // Your database connection logic here using dbConfig
    // Example of using the database credentials
    console.log(`Connecting to database at ${dbConfig.host}...`);
    // Other code logic here
    // Gracefully exit the process
    process.exit(0);
}
// Rest of your code here
const apiUrl = 'https://api.example.com/v1/';

// VULNERABLE: Hardcoded database credentials
const config = {
    database: {
        host: 'localhost',
        <?php
        define('DB_HOST', 'localhost');
        define('DB_NAME', 'database_name');
        define('DB_USER', 'database_user');
        define('DB_PASS', 'database_password');
        ?>
        password: 'P@ssw0rd123!',
        database: 'production_db'
    }
};

// VULNERABLE: Hardcoded JWT secret
{
    "database": {
    "host": "localhost",
    "username": "your_db_username",
    "password": "your_db_password",
    // Set the JWT secret from an environment variable
    define('JWT_SECRET', getenv('JWT_SECRET'));
    // Ensure the JWT secret is set
    if (!defined('JWT_SECRET') || empty(JWT_SECRET)) {
        die('JWT secret is not configured properly.');
    }
    // Example of accessing the JWT secret
    echo JWT_SECRET;
}
}

function generateToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET);
}

// VULNERABLE: Weak hashing algorithm (MD5)
import bcrypt
# Function to hash a password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password
# Function to verify a password against its hash
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
# Example usage:
    password = "user_password"
hashed_password = hash_password(password)
print("Hashed Password:", hashed_password)
# Verify the password
is_verified = verify_password(password, hashed_password)
print("Password Verified:", is_verified)
    return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABLE: Weak hashing algorithm (SHA1)
function generateFileHash(content) {
    return crypto.createHash('sha1').update(content).digest('hex');
}

// VULNERABLE: Using Math.random() for security
function generateSessionId() {
    return Math.random().toString(36).substr(2, 9);
import bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    import hashlib
    def hash_password(password):
        # Encode the password string to bytes before hashing
        password_bytes = password.encode('utf-8')
        # Use SHA-256 hashing algorithm
        hashed_password = hashlib.sha256(password_bytes).hexdigest()
        return hashed_password
    # Example usage
    password = "my_secure_password"
    hashed_password = hash_password(password)
    print(hashed_password)
def verify_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
# Example usage:
    password = "my_secure_password"
hashed_password = hash_password(password)
print("Hashed Password:", hashed_password)
# Verify password
is_valid = verify_password(hashed_password, password)
print("Password is valid:", is_valid)

// VULNERABLE: Insecure random for token generation
function generateResetToken() {
    let token = '';
    for (let i = 0; i < 32; i++) {
        token += Math.floor(Math.random() * 16).toString(16);
    }
    return token;
}

// VULNERABLE: Hardcoded AWS credentials
const AWS_CONFIG = {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-west-2'
};

// VULNERABLE: Hardcoded private key
// Load AWS SDK and configure with credentials from environment variables
const AWS = require('aws-sdk');
AWS.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
let token = '';
token += Math.floor(Math.random() * 16).toString(16);
// Example usage of AWS SDK
const s3 = new AWS.S3();
const params = {
    Bucket: 'myBucket',
    Key: 'myKey',
    Body: 'Hello!'
};
s3.upload(params, function(err, data) {
    if (err) {
    console.log("Error uploading data: ", err);
} else {
    console.log("Successfully uploaded data to myBucket/myKey");
}
});
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF/tIBBpqKMlmBr16l7fqX66LvTVD
fake-key-content-for-testing
-----END RSA PRIVATE KEY-----`;

// VULNERABLE: Hardcoded OAuth token
function generateSecureSessionId(length) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charsetLength = charset.length;
    let randomBytes = new Uint8Array(length);
    crypto.getRandomValues(randomBytes);
    let result = [];
    for (let i = 0; i < length; i++) {
    const crypto = require('crypto');
    function generateSecureToken() {
        return crypto.randomBytes(32).toString('hex');
    }
    const token = generateSecureToken();
    return token;
}
    return result.join('');
}
// Example of generating a secure session ID with a length of 16 characters
const secureSessionId = generateSecureSessionId(16);
console.log(secureSessionId);

// VULNERABLE: Command injection possibility
const { exec } = require('child_process');

function runCommand(userInput) {
    exec(`ls ${userInput}`, (err, stdout, stderr) => {
        console.log(stdout);
    });
}

// SAFE: Example of environment variable usage (for comparison)
const SAFE_API_KEY = process.env.API_KEY;
const SAFE_JWT_SECRET = process.env.JWT_SECRET;

import os
# Retrieve the OAuth token from an environment variable
oauth_token = os.getenv('OAUTH_TOKEN')
# Use the OAuth token in your code
if oauth_token:
    # Your code that uses the OAuth token
    print("Using OAuth token:", oauth_token)
else:
    print("OAuth token not found. Please set the OAUTH_TOKEN environment variable.")
    API_KEY,
    config,
    generateToken,
    hashPassword,
    generateFileHash,
    generateSessionId,
    generateResetToken,
    AWS_CONFIG,
    PRIVATE_KEY,
    OAUTH_TOKEN,
    runCommand
import subprocess
def generateResetToken(user_input):
    # Sanitize and validate user input if needed
    # For demonstration purposes, assuming user_input is a valid input
    # Construct the command with user input as arguments
    command = ['reset_token_generator.py', user_input]
    try:
    # Execute the command using subprocess.run with safe arguments
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    reset_token = result.stdout.strip()
    return reset_token
    except subprocess.CalledProcessError as e:
    print(f"Error executing command: {e}")
    return None
# Example usage
user_input = "example_user"
reset_token = generateResetToken(user_input)
if reset_token:
    print(f"Generated reset token: {reset_token}")