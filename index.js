// server/index.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  jarvisMemory: Object,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// JWT Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Access denied');

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid token');
  }
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      username,
      password: hashedPassword,
      jarvisMemory: { knowledge: [], patterns: [] }
    });
    
    await user.save();
    res.status(201).send('User created');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).send('User not found');

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).send('Invalid password');

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.header('Authorization', token).send({ token });
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.post('/api/learn', authenticate, async (req, res) => {
  try {
    const { input, response } = req.body;
    await User.findByIdAndUpdate(req.user._id, {
      $push: { 'jarvisMemory.knowledge': { input, response } }
    });
    res.send('Memory updated');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get('/api/recall', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json(user.jarvisMemory);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.post('/api/synthesize', authenticate, async (req, res) => {
  try {
    const { text } = req.body;
    // In a real implementation, you might call a TTS service here
    // For now, we'll just return the text with speech markers
    const response = {
      text,
      speech: {
        text: text,
        voice: 'en-US-1', // Voice identifier
        rate: 1.2,        // Speaking rate
        pitch: 1.0        // Pitch adjustment
      }
    };
    res.json(response);
  } catch (err) {
    res.status(400).send(err.message);
  }
});


// Save memory
app.post('/api/memory', authenticate, async (req, res) => {
  try {
    const { input, response } = req.body;
    await User.findByIdAndUpdate(req.user._id, {
      $push: { 'jarvisMemory.knowledge': { input, response } }
    });
    res.json({ message: 'Memory updated' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Load memory
app.get('/api/memory', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json(user.jarvisMemory);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));