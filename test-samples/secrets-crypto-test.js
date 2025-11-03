// Test file for hardcoded secrets and weak crypto vulnerabilities
// This file contains intentional security vulnerabilities for testing purposes

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// VULNERABLE: Hardcoded API key
// Load environment variables from a .env file
// Access the API key from the environment variables
const API_KEY = process.env.API_KEY;
// Check if the API key is present
if (!API_KEY) {
    console.error('API key is missing. Please provide the API key in the environment variables.');
    process.exit(1);
}
// Rest of your code here
const apiUrl = 'https://api.example.com/v1/';

// VULNERABLE: Hardcoded database credentials
const config = {
    database: {
        host: 'localhost',
        user: 'admin',
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
    "database": "your_database_name"
}
}

function generateToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET);
}

// VULNERABLE: Weak hashing algorithm (MD5)
function hashPassword(password) {
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
    return hashed_password
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
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
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
    result.push(charset[randomBytes[i] % charsetLength]);
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

module.exports = {
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
};