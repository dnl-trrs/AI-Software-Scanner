// Test file with intentional security issues

// SQL Injection vulnerability
function getUserData(userId) {
    const query = `SELECT * FROM users WHERE id = ${userId}`;  // Direct value concatenation - SQL Injection risk
    return db.query(query);
}

// Command Injection vulnerability
function executeCommand(userInput) {
    const exec = require('child_process').exec;
    exec(userInput);  // Direct command execution - Command Injection risk
}

// XSS vulnerability
function displayUserInput(input) {
    document.innerHTML = input;  // Direct DOM manipulation - XSS risk
}

// Hardcoded credentials
const password = "mySecretPassword123";  // Hardcoded sensitive data
const apiKey = "sk_test_123456789";

// Path traversal vulnerability
function readUserFile(filename) {
    const fs = require('fs');
    return fs.readFileSync(filename);  // Unsanitized file path - Path Traversal risk
}

// Insecure randomness
function generateToken() {
    return Math.random().toString();  // Weak random number generation
}