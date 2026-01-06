require('dotenv').config();

// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors({
  origin: ['https://flight-requests-frontend.vercel.app', 'http://localhost:5173'],
  credentials: true
}));
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/flight-requests')
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  organization: { type: String, required: true },
  role: { type: String, default: 'client' },
  registeredAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Request Schema
const requestSchema = new mongoose.Schema({
  organization: { type: String, required: true },
  date: { type: String, required: true },
  time: { type: String, required: true },
  area: { type: String, required: true },
  description: { type: String, required: true },
  clientUsername: { type: String, required: true },
  status: { type: String, default: 'pending' },
  feedback: { type: String, default: '' },
  timestamp: { type: Date, default: Date.now }
});

const Request = mongoose.model('Request', requestSchema);

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, organization } = req.body;

    if (!username || !password || !organization) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      password: hashedPassword,
      organization,
      role: 'client'
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check for admin
    if (username === 'admin' && password === 'admin123') {
      const token = jwt.sign(
        { username: 'admin', role: 'admin' },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      return res.json({
        token,
        user: {
          username: 'admin',
          role: 'admin',
          organization: 'Admin'
        }
      });
    }

    // Check for regular user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    const token = jwt.sign(
      { username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        username: user.username,
        role: user.role,
        organization: user.organization
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get all requests (admin) or user's requests (client)
app.get('/api/requests', authenticateToken, async (req, res) => {
  try {
    let requests;
    if (req.user.role === 'admin') {
      requests = await Request.find().sort({ timestamp: -1 });
    } else {
      requests = await Request.find({ clientUsername: req.user.username }).sort({ timestamp: -1 });
    }
    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch requests' });
  }
});

// Create request
app.post('/api/requests', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'client') {
      return res.status(403).json({ error: 'Only clients can create requests' });
    }

    const user = await User.findOne({ username: req.user.username });
    const request = new Request({
      ...req.body,
      organization: user.organization,
      clientUsername: req.user.username
    });

    await request.save();
    res.status(201).json(request);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create request' });
  }
});

// Update request (admin only)
app.patch('/api/requests/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only admin can update requests' });
    }

    const { status, feedback } = req.body;
    const request = await Request.findByIdAndUpdate(
      req.params.id,
      { status, feedback },
      { new: true }
    );

    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }

    res.json(request);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update request' });
  }
});

// Delete request
app.delete('/api/requests/:id', authenticateToken, async (req, res) => {
  try {
    const request = await Request.findById(req.params.id);
    
    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }

    // Only admin or request owner can delete
    if (req.user.role !== 'admin' && request.clientUsername !== req.user.username) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await Request.findByIdAndDelete(req.params.id);
    res.json({ message: 'Request deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete request' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});