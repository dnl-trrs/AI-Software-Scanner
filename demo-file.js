// Demo file to showcase the AI Software Scanner UI
// This file contains intentional security issues for demonstration

const express = require('express');
const app = express();
const mysql = require('mysql');

// SQL Injection vulnerability - line to highlight
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // Vulnerable query - direct string concatenation
// Use parameterized query instead:
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);
    
    connection.query(query, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// Weak random number generation
function generateToken() {
    // Using Math.random() for security tokens is insecure
    return Math.random().toString(36).substring(2);
}

// Password stored in plain text
const config = {
// Move secrets to environment variables:
// 1. Create .env file (don't commit to git)
// 2. Add: API_KEY=your_actual_key
// 3. Use dotenv package:
require('dotenv').config();

password: process.env.PASSWORD // Never store passwords in plain text!
    username: 'admin',
    password: 'password123' // Never store passwords in plain text!
};

// Cross-Site Scripting (XSS) vulnerability
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    // Directly outputting user input without sanitization
    res.send(`<h1>Search results for: ${searchTerm}</h1>`);
});

// Insecure file upload
app.post('/upload', (req, res) => {
    const file = req.files.uploadFile;
    // No file type validation
    file.mv(`./uploads/${file.name}`, (err) => {
        if (err) return res.status(500).send(err);
        res.send('File uploaded!');
    });
});

// Using eval() - extremely dangerous
app.post('/calculate', (req, res) => {
    const expression = req.body.expression;
    // Never use eval with user input!
    const result = eval(expression);
    res.json({ result });
});

// Missing authentication
app.delete('/admin/user/:id', (req, res) => {
    // No authentication check!
    const userId = req.params.id;
    // Delete user logic here
    res.send(`User ${userId} deleted`);
});

// These are the lines that match your Figma mockup
// Lines 61-65 would be here in your actual file
function simulateProcesses() {
    // ExpDistribution example from your mockup
    processes.add(PeriodicProcess({
        name: 'periodic',
        fields: ['duration'],
        fields: ['interarrival-time'],
        fields: ['first-arrival'],
        fields: ['num-repetitions']
    }));
    
    // StochasticProcess example
    processes.add(StochasticProcess({
        name: 'stochastic',
        ExpDistribution: { mean: fields['mean-duration'].toDouble() },
        ExpDistribution: { mean: fields['mean-interarrival-time'].toDouble() },
        fields: ['first-arrival'],
        fields: ['end']
    }));
}

app.listen(3000, () => {
    console.log('Server running on port 3000');
});