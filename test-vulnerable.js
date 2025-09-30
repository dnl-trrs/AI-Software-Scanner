/**
 * Test file with intentional security vulnerabilities
 * This demonstrates the AI Security Scanner capabilities
 */

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const exec = require('child_process').exec;

// VULNERABILITY 1: Hardcoded credentials (Medium severity)
const api_key = "sk_live_4242424242424242424242";
const password = "admin123456";
const secret = "super_secret_key_123";

// VULNERABILITY 2: SQL Injection (Critical severity)
function getUserData(req, res) {
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    
    connection.query(query, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
}

// VULNERABILITY 3: XSS - Cross-site scripting (High severity)
function renderUserContent(req, res) {
    const userInput = req.body.content;
    const html = `
        <div>
            <h1>User Content</h1>
            <div id="content"></div>
            <script>
                document.getElementById('content').innerHTML = '${userInput}';
            </script>
        </div>
    `;
    res.send(html);
}

// VULNERABILITY 4: Path Traversal (Critical severity)
function readUserFile(req, res) {
    const filename = req.query.file;
    const filepath = './uploads/' + filename;
    
    fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
}

// VULNERABILITY 5: Weak Cryptography (Medium severity)
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABILITY 6: Command Injection (Critical severity)
function runCommand(req, res) {
    const userCommand = req.body.command;
    exec('ls -la ' + userCommand, (err, stdout, stderr) => {
        if (err) {
            res.status(500).send(stderr);
        } else {
            res.send(stdout);
        }
    });
}

// VULNERABILITY 7: Insecure Random (Medium severity)
function generateToken() {
    return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}

// VULNERABILITY 8: Another SQL injection example
function searchProducts(searchTerm) {
    const sql = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
    return database.execute(sql);
}

// VULNERABILITY 9: Eval injection
function calculateExpression(req, res) {
    const expression = req.query.expr;
    try {
        const result = eval(expression);
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
}

// VULNERABILITY 10: Sensitive data in logs
function logUserActivity(user) {
    console.log(`User ${user.email} with password ${user.password} logged in`);
}

module.exports = {
    getUserData,
    renderUserContent,
    readUserFile,
    hashPassword,
    runCommand,
    generateToken,
    searchProducts,
    calculateExpression,
    logUserActivity
};