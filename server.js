const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'your-super-secret-key-that-should-be-in-a-env-file';
const USERS_DB_PATH = path.join(__dirname, 'users.json');

// Helper function to read users from the JSON file
const readUsers = () => {
    if (!fs.existsSync(USERS_DB_PATH)) {
        fs.writeFileSync(USERS_DB_PATH, JSON.stringify([]));
    }
    const usersData = fs.readFileSync(USERS_DB_PATH);
    return JSON.parse(usersData);
};

// Helper function to write users to the JSON file
const writeUsers = (users) => {
    fs.writeFileSync(USERS_DB_PATH, JSON.stringify(users, null, 2));
};

// --- API ROUTES ---

// POST /api/signup -> Register a new user
app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    const users = readUsers();

    // Check if user already exists
    if (users.find(user => user.email === email)) {
        return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        id: Date.now().toString(),
        name,
        email,
        password: hashedPassword,
    };

    users.push(newUser);
    writeUsers(users);

    res.status(201).json({ message: 'User registered successfully!' });
});


// POST /api/login -> Authenticate a user
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }
    
    const users = readUsers();
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(404).json({ message: 'No account found with this email.' });
    }

    // Compare the submitted password with the stored hash
    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
        return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Create and sign a JWT token
    const token = jwt.sign(
        { id: user.id, name: user.name },
        JWT_SECRET,
        { expiresIn: '1h' } // Token expires in 1 hour
    );

    res.status(200).json({
        message: 'Login successful!',
        token,
        user: { name: user.name }
    });
});


// --- SERVER START ---
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
