require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cookieParser());
app.use(bodyParser.json());

const mongoURI = process.env.MONGODB_URI;

const secretKey = process.env.SECRET_KEY;

const client = new MongoClient(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

async function connectToMongo() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
    } catch (err) {
        console.error('Error connecting to MongoDB:', err);
    }
}

connectToMongo();

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const db = client.db('login'); 
        const users = db.collection('login_db');

        
        const user = await users.findOne({ username, password });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

    
        const token = jwt.sign({ id: user._id, username: user.username }, secretKey, { expiresIn: '2m' });

    
        res.cookie('token', token, { httpOnly: true });

        res.json({ message: 'Login successful', token });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
    // Registration route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        const db = client.db('login'); // Replace 'your_database_name' with your actual database name
        const users = db.collection('login_db');

        // Check if the username already exists
        const existingUser = await users.findOne({ username });

        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user object
        const newUser = {
            username: username,
            password: hashedPassword // Store the hashed password
        };

        // Insert the new user into the database
        const result = await users.insertOne(newUser);

        res.json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

});


app.get('/logout', (req, res) => {
    // Clear the token cookie
    res.clearCookie('token');
    res.json({ message: 'Logout successful' });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
