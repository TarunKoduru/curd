require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken'); // Import jsonwebtoken for JWT functionality

const app = express();
app.use(express.json()); // To parse incoming JSON data
app.use(cors()); // To allow your frontend to access the API

// MySQL connection
const db = mysql.createConnection({
    host: process.env.DB_HOST, // Load from .env
    user: process.env.DB_USER, // Load from .env
    password: process.env.DB_PASSWORD, // Load from .env
    database: process.env.DB_NAME, // Load from .env
});

db.connect((err) => {
    if (err) {
        console.error('Database connection error:', err);
        process.exit(1); // Exit the process on connection failure
    }
    console.log('Connected to MySQL database');
});

// Middleware to check if the user is authenticated using JWT token
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', ''); // Extract token from the request header
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Forbidden: Invalid token' });
        }
        req.user = user; // Attach the user info to the request object
        next(); // Proceed to the next middleware or route handler
    });
};

// API route for user sign up (Create)
app.post('/api/signup', async (req, res) => {
    const { firstName, lastName, username, email, password } = req.body;

    if (!firstName || !lastName || !username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const query = 'INSERT INTO users (firstName, lastName, username, email, password) VALUES (?, ?, ?, ?, ?)';
        db.query(query, [firstName, lastName, username, email, hashedPassword], (err, result) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error', error: err.sqlMessage });
            }
            res.status(201).json({ message: 'User created successfully', userId: result.insertId });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// API route for user sign in (Read)
app.post('/api/signin', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error', error: err.sqlMessage });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });

        res.status(200).json({ message: 'Login successful', token }); // Send token to the client
    });
});

// Get all users (Read all) - Protected
app.get('/api/users', authenticateToken, (req, res) => {
    const query = 'SELECT id, firstName, lastName, username, email FROM users';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error', error: err.sqlMessage });
        }
        res.status(200).json(results);
    });
});

// Get a specific user by ID (Read one)
app.get('/api/users/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const query = 'SELECT id, firstName, lastName, username, email FROM users WHERE id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error', error: err.sqlMessage });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json(results[0]);
    });
});

// Update a user (Update) - Protected
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { firstName, lastName, username, email, password } = req.body;

    if (!firstName || !lastName || !username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const query = 'UPDATE users SET firstName = ?, lastName = ?, username = ?, email = ?, password = ? WHERE id = ?';
        db.query(query, [firstName, lastName, username, email, hashedPassword, id], (err, result) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error', error: err.sqlMessage });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            res.status(200).json({ message: 'User updated successfully' });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete a user (Delete) - Protected
app.delete('/api/users/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM users WHERE id = ?';
    db.query(query, [id], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error', error: err.sqlMessage });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ message: 'User deleted successfully' });
    });
});

// Root route
app.get('/', (req, res) => {
    res.send('Welcome to the API! Use /api/signup to sign up and /api/signin to sign in.');
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
