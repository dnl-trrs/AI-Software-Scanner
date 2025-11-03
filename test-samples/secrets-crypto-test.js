// Test file for hardcoded secrets and weak crypto vulnerabilities
// This file contains intentional security vulnerabilities for testing purposes

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// VULNERABLE: Hardcoded API key
const API_KEY = 'sk-1234567890abcdef1234567890abcdef';
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
const JWT_SECRET = 'my-super-secret-key-123';

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
}

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
const OAUTH_TOKEN = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ';

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