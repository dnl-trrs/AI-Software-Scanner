/**
 * Test Web Application - E-commerce Backend
 * Contains realistic security vulnerabilities for testing
 * DO NOT USE IN PRODUCTION!
 */

const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const app = express();

// ========== DATABASE CONNECTION ==========

// 1. Database credentials exposed
const dbConfig = {
    host: 'localhost',
    user: 'admin',
    password: 'Admin123!@#', // BAD: Hardcoded database password
    database: 'ecommerce_db'
};

const db = mysql.createConnection(dbConfig);

// ========== USER AUTHENTICATION ==========

// 2. Weak password hashing
function hashPassword(password) {
    // BAD: Using MD5 instead of bcrypt
    const crypto = require('crypto');
    return crypto.createHash('md5').update(password).digest('hex');
}

// 3. SQL Injection in login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // BAD: Direct string concatenation in SQL
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${hashPassword(password)}'`;
    
    db.query(query, (err, results) => {
        if (results.length > 0) {
            // 4. Weak JWT secret
            const token = jwt.sign(
                { userId: results[0].id }, 
                'secret123', // BAD: Hardcoded weak secret
                { expiresIn: '24h' }
            );
            res.json({ token });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// 5. No rate limiting on login attempts
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    // BAD: No rate limiting allows brute force attacks
    const resetToken = Math.random().toString(36); // BAD: Weak token generation
    
    // 6. Password reset token in URL
    const resetLink = `http://example.com/reset?token=${resetToken}&email=${email}`; // BAD: Token in URL
    
    res.json({ message: 'Reset link sent' });
});

// ========== PRODUCT MANAGEMENT ==========

// 7. NoSQL Injection vulnerability
app.get('/api/products/search', (req, res) => {
    const searchQuery = req.query.q;
    
    // BAD: Direct use of user input in MongoDB query
    db.collection('products').find({
        $where: `this.name.includes('${searchQuery}')`
    }).toArray((err, products) => {
        res.json(products);
    });
});

// 8. XSS in product reviews
app.post('/api/products/:id/reviews', (req, res) => {
    const { rating, comment } = req.body;
    const productId = req.params.id;
    
    // BAD: No HTML sanitization
    const reviewHtml = `
        <div class="review">
            <p>${comment}</p>
            <span>Rating: ${rating}/5</span>
        </div>
    `;
    
    // Store review without sanitization
    db.query(`INSERT INTO reviews (product_id, html_content) VALUES (?, ?)`, 
        [productId, reviewHtml]
    );
    
    res.json({ success: true });
});

// ========== FILE OPERATIONS ==========

// 9. Path traversal in file download
app.get('/api/download/:filename', (req, res) => {
    const filename = req.params.filename;
    
    // BAD: No path validation
    const filePath = path.join(__dirname, 'uploads', filename);
    res.download(filePath);
});

// 10. Unrestricted file upload
app.post('/api/upload', (req, res) => {
    const uploadedFile = req.files.file;
    
    // BAD: No file type validation
    const savePath = `./uploads/${uploadedFile.name}`;
    uploadedFile.mv(savePath, (err) => {
        if (err) return res.status(500).send(err);
        res.json({ path: savePath });
    });
});

// 11. Directory listing exposure
app.get('/api/files', (req, res) => {
    const dirPath = req.query.path || './';
    
    // BAD: Exposing directory structure
    fs.readdir(dirPath, (err, files) => {
        res.json({ files });
    });
});

// ========== PAYMENT PROCESSING ==========

// 12. Credit card data in logs
function processPayment(cardNumber, cvv, amount) {
    // BAD: Logging sensitive payment data
    console.log(`Processing payment: Card ${cardNumber}, CVV ${cvv}, Amount $${amount}`);
    
    // 13. Storing card data unencrypted
    db.query(
        'INSERT INTO payments (card_number, cvv, amount) VALUES (?, ?, ?)',
        [cardNumber, cvv, amount] // BAD: Storing plain text card data
    );
}

// 14. IDOR in order details
app.get('/api/orders/:orderId', (req, res) => {
    const orderId = req.params.orderId;
    
    // BAD: No authorization check - any user can view any order
    db.query('SELECT * FROM orders WHERE id = ?', [orderId], (err, order) => {
        res.json(order);
    });
});

// ========== API ENDPOINTS ==========

// 15. API key in query string
app.get('/api/external-service', async (req, res) => {
    const apiKey = 'sk_live_4242424242424242'; // BAD: Hardcoded API key
    
    // BAD: API key in URL
    const response = await fetch(`https://api.service.com/data?key=${apiKey}`);
    res.json(await response.json());
});

// 16. CORS misconfiguration
app.use((req, res, next) => {
    // BAD: Allowing all origins with credentials
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', '*');
    next();
});

// 17. GraphQL introspection in production
const graphqlEndpoint = {
    introspection: true, // BAD: Should be false in production
    playground: true,    // BAD: GraphQL playground in production
};

// ========== SESSION MANAGEMENT ==========

// 18. Session fixation vulnerability
app.post('/api/session', (req, res) => {
    const sessionId = req.body.sessionId || generateSessionId();
    
    // BAD: Accepting session ID from client
    req.session.id = sessionId;
    res.cookie('session', sessionId, {
        // 19. Missing secure cookie flags
        // BAD: Missing httpOnly, secure, sameSite
    });
    
    res.json({ sessionId });
});

// 20. Predictable session tokens
function generateSessionId() {
    // BAD: Using timestamp for session ID
    return 'sess_' + Date.now().toString();
}

// ========== USER DATA OPERATIONS ==========

// 21. Mass assignment vulnerability
app.put('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const userData = req.body;
    
    // BAD: Allowing all fields to be updated including role/admin
    const query = 'UPDATE users SET ? WHERE id = ?';
    db.query(query, [userData, userId], (err, result) => {
        res.json({ updated: true });
    });
});

// 22. Sensitive data in response
app.get('/api/users', (req, res) => {
    // BAD: Returning passwords and sensitive data
    db.query('SELECT * FROM users', (err, users) => {
        res.json(users); // Includes passwords, SSNs, etc.
    });
});

// ========== ADMIN OPERATIONS ==========

// 23. Command injection in backup
app.post('/api/admin/backup', (req, res) => {
    const backupName = req.body.name;
    
    // BAD: Command injection vulnerability
    const { exec } = require('child_process');
    exec(`tar -czf backups/${backupName}.tar.gz ./data/`, (error, stdout) => {
        res.json({ backup: stdout });
    });
});

// 24. XML External Entity (XXE)
app.post('/api/import', (req, res) => {
    const xmlData = req.body.xml;
    const parser = require('xml2js');
    
    // BAD: XXE vulnerability - no entity restriction
    parser.parseString(xmlData, { 
        explicitArray: false,
        ignoreAttrs: false
        // Missing: DTD and entity processing disabled
    }, (err, result) => {
        res.json(result);
    });
});

// ========== CACHING & PERFORMANCE ==========

// 25. Race condition in discount application
let discountUsed = false;
app.post('/api/apply-discount', async (req, res) => {
    const { code, orderId } = req.body;
    
    // BAD: Race condition - check and set not atomic
    if (!discountUsed) {
        await applyDiscount(orderId, code);
        discountUsed = true;
        res.json({ success: true });
    } else {
        res.json({ error: 'Discount already used' });
    }
});

// 26. Regex DoS vulnerability
app.post('/api/validate-email', (req, res) => {
    const email = req.body.email;
    
    // BAD: Catastrophic backtracking regex
    const emailRegex = /^([a-zA-Z0-9_\.\-]+)@(([a-zA-Z0-9\-]+\.)+)([a-zA-Z]{2,4})+$/;
    
    if (emailRegex.test(email)) {
        res.json({ valid: true });
    } else {
        res.json({ valid: false });
    }
});

// ========== LOGGING & MONITORING ==========

// 27. Insufficient logging
app.delete('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    
    // BAD: No audit logging for critical operations
    db.query('DELETE FROM users WHERE id = ?', [userId]);
    res.json({ deleted: true });
});

// 28. Error messages leak information
app.get('/api/debug', (req, res) => {
    try {
        // Some operation
    } catch (error) {
        // BAD: Exposing stack trace and internal details
        res.status(500).json({
            error: error.message,
            stack: error.stack,
            config: dbConfig // Exposing database config
        });
    }
});

// ========== ENCRYPTION & CRYPTO ==========

// 29. Using ECB mode encryption
function encryptData(data) {
    const crypto = require('crypto');
    const algorithm = 'aes-128-ecb'; // BAD: ECB mode is insecure
    const key = 'mysecretkey12345'; // BAD: Hardcoded key
    
    const cipher = crypto.createCipher(algorithm, key);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// 30. Timing attack vulnerability
function verifyApiKey(providedKey) {
    const validKey = 'api_key_abcdef123456';
    
    // BAD: String comparison vulnerable to timing attacks
    return providedKey === validKey;
}

// ========== SERVER CONFIGURATION ==========

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => { // BAD: Listening on all interfaces
    console.log(`Server running on port ${PORT}`);
    console.log(`Database password: ${dbConfig.password}`); // BAD: Logging secrets
});

module.exports = app;