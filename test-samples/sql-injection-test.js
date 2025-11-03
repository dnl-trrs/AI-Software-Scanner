// Test file for SQL Injection vulnerabilities
// This file contains intentional security vulnerabilities for testing purposes

const mysql = require('mysql');
const express = require('express');
const app = express();

// VULNERABLE: Direct SQL concatenation
function getUserById(userId) {
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    return db.query(query);
}

// VULNERABLE: Template literal injection
function searchProducts(searchTerm) {
    const sql = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
    return database.execute(sql);
}

// VULNERABLE: String concatenation with user input
app.get('/user', (req, res) => {
    const username = req.query.username;
    const password = req.query.password;
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    
    db.query(query, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// VULNERABLE: Dynamic table name
function getDataFromTable(tableName, id) {
    const query = `SELECT * FROM ${tableName} WHERE id = ${id}`;
    return db.query(query);
}

// VULNERABLE: Multiple parameters concatenated
function updateUserEmail(userId, newEmail) {
    const updateQuery = "UPDATE users SET email = '" + newEmail + "' WHERE id = " + userId;
    return db.execute(updateQuery);
}

// SAFE: Example of parameterized query (for comparison)
function safeGetUserById(userId) {
    const query = "SELECT * FROM users WHERE id = ?";
    return db.query(query, [userId]);
}

module.exports = {
    getUserById,
    searchProducts,
    getDataFromTable,
    updateUserEmail,
    safeGetUserById
};