require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();

// Enhanced CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', apiLimiter);

app.use(express.json());

// MongoDB Connection with enhanced settings
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Enhanced Schemas
const MemoryEntrySchema = new mongoose.Schema({
  id: { type: String, default: uuidv4 },
  input: { type: String, required: true },
  response: { type: String, required: true },
  confidence: { type: Number, default: 0.5 },
  lastUsed: { type: Date, default: Date.now }
});

const PatternSchema = new mongoose.Schema({
  word: { type: String, required: true, index: true },
  responses: [{ type: String }]
});

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true, index: true },
  password: { type: String, required: true },
  jarvisMemory: {
    knowledge: [MemoryEntrySchema],
    patterns: [PatternSchema]
  },
  refreshToken: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// JWT helpers
const generateAccessToken = (userId) => {
  return jwt.sign({ _id: userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
};

const generateRefreshToken = () => {
  return jwt.sign({}, process.env.REFRESH_SECRET, { expiresIn: '7d' });
};

// Authentication middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded._id).select('-password -refreshToken');
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      username,
      password: hashedPassword,
      jarvisMemory: { knowledge: [], patterns: [] }
    });
    
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(400).json({ 
      error: err.code === 11000 ? 'Username already exists' : 'Registration failed' 
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken();
    
    user.refreshToken = refreshToken;
    await user.save();

    res.json({
      accessToken,
      refreshToken,
      user: { id: user._id, username: user.username }
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token required' });

  try {
    const user = await User.findOne({ refreshToken });
    if (!user) return res.status(403).json({ error: 'Invalid refresh token' });

    jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    const newAccessToken = generateAccessToken(user._id);
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired refresh token' });
  }
});

// Memory operations
app.post('/api/memory', authenticate, async (req, res) => {
  try {
    const { input, response } = req.body;
    await User.findByIdAndUpdate(req.user._id, {
      $push: { 
        'jarvisMemory.knowledge': { 
          input, 
          response,
          lastUsed: new Date()
        } 
      }
    });
    res.json({ message: 'Memory updated' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/memory', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('jarvisMemory -_id');
    res.json(user.jarvisMemory);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// TTS endpoint
app.post('/api/synthesize', authenticate, async (req, res) => {
  try {
    const { text } = req.body;
    // In production, integrate with a TTS service here
    res.json({
      text,
      speech: {
        text,
        voice: 'en-US-Wavenet-D',
        rate: 1.1,
        pitch: 0.9
      }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));