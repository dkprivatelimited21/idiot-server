require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const validator = require('validator');

const app = express();

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'REFRESH_SECRET', 'MONGODB_URI'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
if (missingEnvVars.length > 0) {
  console.error('Missing required environment variables:', missingEnvVars.join(', '));
  process.exit(1);
}

// Middleware setup
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP, please try again later' }
});

app.use('/api/', generalLimiter);
app.use(express.json({ limit: '10mb' }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Enhanced AI Learning Schemas
const ConversationContextSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, index: true },
  messages: [{
    type: { type: String, enum: ['user', 'assistant'], required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    confidence: { type: Number, default: 1.0 }
  }],
  topic: String,
  lastActive: { type: Date, default: Date.now }
});

const LearningEntrySchema = new mongoose.Schema({
  id: { type: String, default: uuidv4, index: true },
  
  // Input analysis
  input: {
    original: { type: String, required: true },
    normalized: { type: String, required: true, index: true },
    keywords: [{ type: String, index: true }],
    intent: { type: String, index: true },
    entities: [{
      type: { type: String },
      value: { type: String },
      confidence: { type: Number }
    }],
    embedding: [Number] // For similarity search (would use actual embeddings in production)
  },
  
  // Response data
  response: {
    text: { type: String, required: true },
    confidence: { type: Number, default: 0.5, min: 0, max: 1 },
    source: { type: String, enum: ['user_taught', 'ai_generated', 'fallback'], default: 'ai_generated' },
    successCount: { type: Number, default: 0 },
    failureCount: { type: Number, default: 0 }
  },
  
  // Learning metadata
  context: {
    previousQuery: String,
    sessionId: String,
    topic: String
  },
  
  // Performance tracking
  usage: {
    timesUsed: { type: Number, default: 0 },
    lastUsed: { type: Date, default: Date.now },
    averageRating: { type: Number, default: 0 },
    feedbackCount: { type: Number, default: 0 }
  },
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const IntentPatternSchema = new mongoose.Schema({
  intent: { type: String, required: true, index: true },
  patterns: [{
    pattern: { type: String, required: true },
    confidence: { type: Number, default: 1.0 },
    examples: [String]
  }],
  responses: [{
    template: { type: String, required: true },
    confidence: { type: Number, default: 1.0 },
    conditions: [{
      entity: String,
      operator: String,
      value: String
    }]
  }],
  createdAt: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
  username: { 
    type: String, 
    unique: true, 
    required: true, 
    index: true,
    trim: true,
    lowercase: true
  },
  password: { type: String, required: true },
  
  // AI Learning Data
  aiMemory: {
    learningEntries: [LearningEntrySchema],
    intentPatterns: [IntentPatternSchema],
    conversations: [ConversationContextSchema],
    
    // Learning preferences
    preferences: {
      learningRate: { type: Number, default: 0.1 },
      confidenceThreshold: { type: Number, default: 0.7 },
      maxMemorySize: { type: Number, default: 10000 },
      enableAutoLearning: { type: Boolean, default: true }
    },
    
    // Performance stats
    stats: {
      totalQueries: { type: Number, default: 0 },
      successfulResponses: { type: Number, default: 0 },
      learningInteractions: { type: Number, default: 0 },
      averageConfidence: { type: Number, default: 0 },
      lastLearningDate: Date
    }
  },
  
  refreshToken: String,
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

const User = mongoose.model('User', UserSchema);

// AI Learning Helper Functions
class AILearningEngine {
  
  // Simple text similarity (in production, use proper embeddings)
  static calculateSimilarity(text1, text2) {
    const words1 = text1.toLowerCase().split(' ');
    const words2 = text2.toLowerCase().split(' ');
    const intersection = words1.filter(word => words2.includes(word));
    const union = [...new Set([...words1, ...words2])];
    return intersection.length / union.length;
  }
  
  // Extract keywords and normalize input
  static analyzeInput(input) {
    const normalized = input.toLowerCase().trim();
    const keywords = normalized
      .split(/\W+/)
      .filter(word => word.length > 2)
      .filter(word => !['the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'].includes(word));
    
    // Simple intent classification
    let intent = 'general';
    if (normalized.includes('time') || normalized.includes('clock')) intent = 'time_query';
    else if (normalized.includes('weather')) intent = 'weather_query';
    else if (normalized.includes('calculate') || normalized.includes('math')) intent = 'calculation';
    else if (normalized.includes('open') || normalized.includes('navigate')) intent = 'navigation';
    else if (['hello', 'hi', 'hey'].some(greeting => normalized.includes(greeting))) intent = 'greeting';
    
    return { normalized, keywords, intent };
  }
  
  // Find similar learning entries
  static async findSimilarEntries(userId, input, threshold = 0.3) {
    const user = await User.findById(userId);
    if (!user) return [];
    
    const { normalized } = this.analyzeInput(input);
    const similar = [];
    
    for (const entry of user.aiMemory.learningEntries) {
      const similarity = this.calculateSimilarity(normalized, entry.input.normalized);
      if (similarity > threshold) {
        similar.push({
          entry,
          similarity,
          confidence: entry.response.confidence * similarity
        });
      }
    }
    
    return similar.sort((a, b) => b.confidence - a.confidence);
  }
  
  // Update confidence based on feedback
  static updateConfidence(entry, isPositive, learningRate = 0.1) {
    const adjustment = isPositive ? learningRate : -learningRate;
    entry.response.confidence = Math.max(0, Math.min(1, entry.response.confidence + adjustment));
    
    if (isPositive) {
      entry.response.successCount++;
      entry.usage.timesUsed++;
    } else {
      entry.response.failureCount++;
    }
    
    entry.usage.lastUsed = new Date();
    entry.updatedAt = new Date();
    
    return entry;
  }
}

// Authentication middleware (same as before)
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const user = await User.findById(decoded._id).select('-password -refreshToken');
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Authentication failed' });
  }
};

// Enhanced AI Learning Routes

// Process user input with AI learning
app.post('/api/ai/process', authenticate, async (req, res) => {
  try {
    const { input, sessionId, context } = req.body;
    
    if (!input) {
      return res.status(400).json({ error: 'Input is required' });
    }

    const user = await User.findById(req.user._id);
    const analysis = AILearningEngine.analyzeInput(input);
    
    // Update user stats
    user.aiMemory.stats.totalQueries++;
    
    // Find similar entries
    const similarEntries = await AILearningEngine.findSimilarEntries(req.user._id, input);
    
    let response = null;
    let confidence = 0;
    let source = 'fallback';
    
    if (similarEntries.length > 0 && similarEntries[0].confidence > user.aiMemory.preferences.confidenceThreshold) {
      // Use learned response
      const bestMatch = similarEntries[0];
      response = bestMatch.entry.response.text;
      confidence = bestMatch.confidence;
      source = bestMatch.entry.response.source;
      
      // Update usage stats
      bestMatch.entry.usage.timesUsed++;
      bestMatch.entry.usage.lastUsed = new Date();
      
    } else {
      // Generate new response (simplified - in production use actual AI)
      const responses = await generateResponse(analysis, context);
      response = responses.text;
      confidence = responses.confidence;
      source = 'ai_generated';
      
      // Auto-learn if enabled
      if (user.aiMemory.preferences.enableAutoLearning) {
        const newEntry = {
          id: uuidv4(),
          input: {
            original: input,
            normalized: analysis.normalized,
            keywords: analysis.keywords,
            intent: analysis.intent
          },
          response: {
            text: response,
            confidence: confidence,
            source: source
          },
          context: {
            sessionId: sessionId,
            topic: context?.topic
          },
          createdAt: new Date()
        };
        
        user.aiMemory.learningEntries.push(newEntry);
        user.aiMemory.stats.learningInteractions++;
      }
    }
    
    // Update conversation context
    if (sessionId) {
      let conversation = user.aiMemory.conversations.find(c => c.sessionId === sessionId);
      if (!conversation) {
        conversation = {
          sessionId,
          messages: [],
          lastActive: new Date()
        };
        user.aiMemory.conversations.push(conversation);
      }
      
      conversation.messages.push(
        { type: 'user', content: input, timestamp: new Date() },
        { type: 'assistant', content: response, confidence, timestamp: new Date() }
      );
      conversation.lastActive = new Date();
    }
    
    await user.save();
    
    res.json({
      text: response,
      confidence: confidence,
      source: source,
      intent: analysis.intent,
      keywords: analysis.keywords,
      sessionId: sessionId
    });
    
  } catch (err) {
    console.error('AI processing error:', err);
    res.status(500).json({ error: 'Failed to process input' });
  }
});

// Provide feedback on AI response
app.post('/api/ai/feedback', authenticate, async (req, res) => {
  try {
    const { sessionId, messageIndex, rating, correction } = req.body;
    
    const user = await User.findById(req.user._id);
    const conversation = user.aiMemory.conversations.find(c => c.sessionId === sessionId);
    
    if (!conversation || !conversation.messages[messageIndex]) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    const message = conversation.messages[messageIndex];
    if (message.type !== 'assistant') {
      return res.status(400).json({ error: 'Can only provide feedback on assistant messages' });
    }
    
    const userInput = messageIndex > 0 ? conversation.messages[messageIndex - 1].content : null;
    
    // Find the corresponding learning entry
    const learningEntry = user.aiMemory.learningEntries.find(entry => 
      entry.input.original === userInput && entry.response.text === message.content
    );
    
    if (learningEntry) {
      // Update existing entry
      const isPositive = rating >= 3; // Assuming 1-5 rating scale
      AILearningEngine.updateConfidence(learningEntry, isPositive, user.aiMemory.preferences.learningRate);
      
      learningEntry.usage.averageRating = 
        (learningEntry.usage.averageRating * learningEntry.usage.feedbackCount + rating) / 
        (learningEntry.usage.feedbackCount + 1);
      learningEntry.usage.feedbackCount++;
      
    } else if (correction && userInput) {
      // Create new learning entry with corrected response
      const analysis = AILearningEngine.analyzeInput(userInput);
      user.aiMemory.learningEntries.push({
        id: uuidv4(),
        input: {
          original: userInput,
          normalized: analysis.normalized,
          keywords: analysis.keywords,
          intent: analysis.intent
        },
        response: {
          text: correction,
          confidence: 0.8,
          source: 'user_taught'
        },
        context: { sessionId },
        createdAt: new Date()
      });
      
      user.aiMemory.stats.learningInteractions++;
    }
    
    await user.save();
    
    res.json({ message: 'Feedback recorded successfully' });
    
  } catch (err) {
    console.error('Feedback error:', err);
    res.status(500).json({ error: 'Failed to record feedback' });
  }
});

// Get AI learning statistics
app.get('/api/ai/stats', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    const stats = {
      ...user.aiMemory.stats,
      memorySize: user.aiMemory.learningEntries.length,
      conversationCount: user.aiMemory.conversations.length,
      intentPatterns: user.aiMemory.intentPatterns.length,
      
      // Calculate average confidence
      averageConfidence: user.aiMemory.learningEntries.length > 0 
        ? user.aiMemory.learningEntries.reduce((sum, entry) => sum + entry.response.confidence, 0) / user.aiMemory.learningEntries.length
        : 0,
      
      // Top intents
      topIntents: getTopIntents(user.aiMemory.learningEntries),
      
      // Recent learning activity
      recentLearning: user.aiMemory.learningEntries
        .filter(entry => entry.createdAt > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000))
        .length
    };
    
    res.json(stats);
    
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to retrieve statistics' });
  }
});

// Manual teaching endpoint
app.post('/api/ai/teach', authenticate, async (req, res) => {
  try {
    const { input, response, intent } = req.body;
    
    if (!input || !response) {
      return res.status(400).json({ error: 'Input and response are required' });
    }
    
    const user = await User.findById(req.user._id);
    const analysis = AILearningEngine.analyzeInput(input);
    
    const newEntry = {
      id: uuidv4(),
      input: {
        original: input,
        normalized: analysis.normalized,
        keywords: analysis.keywords,
        intent: intent || analysis.intent
      },
      response: {
        text: response,
        confidence: 0.9, // High confidence for manually taught responses
        source: 'user_taught'
      },
      createdAt: new Date()
    };
    
    user.aiMemory.learningEntries.push(newEntry);
    user.aiMemory.stats.learningInteractions++;
    user.aiMemory.stats.lastLearningDate = new Date();
    
    await user.save();
    
    res.json({ message: 'Teaching recorded successfully', entryId: newEntry.id });
    
  } catch (err) {
    console.error('Teaching error:', err);
    res.status(500).json({ error: 'Failed to record teaching' });
  }
});

// Helper functions
function getTopIntents(entries) {
  const intentCounts = {};
  entries.forEach(entry => {
    const intent = entry.input.intent;
    intentCounts[intent] = (intentCounts[intent] || 0) + 1;
  });
  
  return Object.entries(intentCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([intent, count]) => ({ intent, count }));
}

async function generateResponse(analysis, context) {
  // Simplified response generation - in production, integrate with actual AI
  const { intent, keywords } = analysis;
  
  let text = "I understand you're asking about something, but I need to learn more to give you a better response.";
  let confidence = 0.3;
  
  switch (intent) {
    case 'time_query':
      text = `The current time is ${new Date().toLocaleTimeString()}.`;
      confidence = 0.9;
      break;
    case 'weather_query':
      text = "I'd need to connect to a weather service to get current weather information.";
      confidence = 0.7;
      break;
    case 'greeting':
      text = "Hello! How can I help you today?";
      confidence = 0.9;
      break;
    case 'calculation':
      // Basic math would go here
      text = "I can help with basic calculations. What would you like me to calculate?";
      confidence = 0.8;
      break;
    default:
      if (keywords.length > 0) {
        text = `I see you mentioned ${keywords.slice(0, 3).join(', ')}. Could you provide more details so I can help better?`;
        confidence = 0.5;
      }
  }
  
  return { text, confidence };
}

// Health check and other routes (same as before)
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 AI Learning Server running on port ${PORT}`);
});