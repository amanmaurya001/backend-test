const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto'); // Using Node's built-in crypto module for hashing
const jwt = require('jsonwebtoken');
const xss = require('xss');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet'); // Added for security headers
require('dotenv').config();

const app = express();

// Trust proxy - essential for Render.com and other hosting services that use proxies
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// Secret keys - use environment variables
const SECRET_KEY = process.env.SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = process.env.JWT_EXPIRY; // Changed from 1m to 1h to match frontend expectation

// Security Middleware - Apply Helmet for security headers
app.use(helmet()); // This adds multiple security headers

// Additional custom security headers
app.use((req, res, next) => {
  // Force HTTPS - redirect HTTP to HTTPS
  if (process.env.NODE_ENV === 'production' && !req.secure && req.get('x-forwarded-proto') !== 'https') {
    return res.redirect('https://' + req.get('host') + req.url);
  }
  
  // Strict-Transport-Security header with long max-age
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  
  // Content-Security-Policy - restricts sources of content
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'");
  
  // X-Content-Type-Options - prevents MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // X-Frame-Options - prevents clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // X-XSS-Protection - provides XSS protection in older browsers
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Referrer-Policy - controls amount of referrer info sent
  res.setHeader('Referrer-Policy', 'same-origin');
  
  // Feature-Policy - controls browser features
  res.setHeader('Feature-Policy', "camera 'none'; microphone 'none'; geolocation 'none'");
  
  // Permissions-Policy - newer version of Feature-Policy
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  
  next();
});

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.ALLOWED_ORIGIN 
    : ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:5500','http://127.0.0.1:5501','https://amanmaurya001.github.io','http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
allowedHeaders: [
    'Content-Type', 
    'Authorization',
    'X-CSRF-Token',              // Add this line
    'X-Requested-With',
    'Accept',
    'Origin'
  ],
  optionsSuccessStatus: 200
}));
app.use(bodyParser.json({ limit: '100kb' })); // Limit request size

// Sanitization middleware
const sanitizeRequest = (req, res, next) => {
  // Sanitize body
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        // Apply XSS sanitization to string values
        req.body[key] = xss(req.body[key]);
      } else if (typeof req.body[key] === 'object' && req.body[key] !== null) {
        // Recursively sanitize nested objects (like address)
        sanitizeObject(req.body[key]);
      }
    });
  }
  
  // Continue to next middleware
  next();
};

// Helper function to sanitize objects recursively
function sanitizeObject(obj) {
  if (!obj || typeof obj !== 'object') return;
  
  Object.keys(obj).forEach(key => {
    if (typeof obj[key] === 'string') {
      obj[key] = xss(obj[key]);
    } else if (typeof obj[key] === 'object' && obj[key] !== null) {
      if (Array.isArray(obj[key])) {
        obj[key].forEach((item, index) => {
          if (typeof item === 'string') {
            obj[key][index] = xss(item);
          } else if (typeof item === 'object' && item !== null) {
            sanitizeObject(item);
          }
        });
      } else {
        sanitizeObject(obj[key]);
      }
    }
  });
}

// Email validation helper
function isValidEmail(email) {
  return validator.isEmail(email);
}

// MongoDB data sanitization helper
function sanitizeMongoQuery(query) {
  // Check if query has MongoDB operators
  const hasDollarKey = Object.keys(query).some(key => key.startsWith('$'));
  if (hasDollarKey) {
    throw new Error('Invalid query format');
  }
  return query;
}

// Apply sanitization middleware globally
app.use(sanitizeRequest);

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ success: false, message: 'Authorization header missing' });
  }

  const token = authHeader.split(' ')[1]; // Format: "Bearer TOKEN"
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'Token not provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.clientId = decoded.clientId;
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};

// Rate limiters
// Email subscription rate limiter - 3 attempts per hour per IP
const subscribeRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 3, // 3 requests per window
  standardHeaders: true, // Return rate limit info in headers
  message: { error: 'Too many subscription attempts. Please try again later.' }
});

// API general rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in headers
  message: { error: 'Too many requests. Please try again later.' }
});

// Apply general rate limiter to all API routes
app.use('/api/', apiLimiter);

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error'
  });
};

// MongoDB Connection - Using a single MongoDB URI for everything
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/estrella';

// Determine if we're using MongoDB Atlas (connection string contains "mongodb+srv")
const isUsingAtlas = MONGO_URI.includes('mongodb+srv');

// MongoDB connection options
const mongoOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true
};

// Add additional options for Atlas connections
if (isUsingAtlas) {
  mongoOptions.serverSelectionTimeoutMS = 5000; // Timeout after 5s instead of 30s
  mongoOptions.socketTimeoutMS = 45000; // Close sockets after 45s of inactivity
}

// Connect to MongoDB
mongoose.connect(MONGO_URI, mongoOptions)
  .then(() => console.log(`Connected to MongoDB database: ${isUsingAtlas ? 'Atlas' : 'Local'}`))
  .catch(err => console.error('Failed to connect to MongoDB database:', err));

// Email Schema & Model
const emailSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: v => /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(v),
      message: props => `${props.value} is not a valid email address!`
    }
  },
  subscriptionDate: { type: Date, default: Date.now }
});

// Add index to email field
emailSchema.index({ email: 1 }, { unique: true });
const Email = mongoose.model('emails', emailSchema);

// Product Schema & Model
const productSchema = new mongoose.Schema({
  product_code: String,
  product_name: String,
  product_price: Number,
  product_imageurl: String
}, { strict: false });

// Add index to product_code field
productSchema.index({ product_code: 1 });
const Product = mongoose.model('product', productSchema);

// Order Schema & Model - now using the same connection as everything else
const orderSchema = new mongoose.Schema({
  cart: Array,
  address: Object,
  pricing: Object,
  orderDate: { type: Date, default: Date.now },
  status: { type: String, default: 'pending' }
}, { strict: false });

// Add composite index for better query performance
orderSchema.index({ orderDate: -1, status: 1 });

// Create Order model using the same connection
const Order = mongoose.model('orders', orderSchema);

// Helper function to generate order hash
function generateOrderHash(order) {
  // Create a string representation of the order to hash
  // This should include all relevant order details that shouldn't be tampered with
  const orderString = JSON.stringify({
    cart: order.cart.map(item => ({
      productCode: item.productCode,
      productName: item.productName,
      price: item.price,
      size: item.size
    })),
    address: order.address,
    pricing: order.pricing
  });
  
  // Create a hash using HMAC with SHA-256
  return crypto.createHmac('sha256', SECRET_KEY)
              .update(orderString)
              .digest('hex');
}

// Helper function to verify order hash
function verifyOrderHash(order, hash) {
  const computedHash = generateOrderHash(order);
  return computedHash === hash;
}

// Token generation endpoint
app.post('/api/get-token', (req, res) => {
  const clientId = crypto.randomBytes(16).toString('hex'); // Generate random client ID
  
  // Create JWT token
  const token = jwt.sign(
    { clientId: clientId }, 
    JWT_SECRET, 
    { expiresIn: JWT_EXPIRY }
  );
  
  res.status(200).json({ 
    success: true, 
    token: token 
  });
});

// Email subscription endpoint - protected with JWT and rate limited
app.post('/api/subscribe', subscribeRateLimiter, authenticateJWT, async (req, res) => {
  try {
    // Get and validate email
    const email = req.body.email ? req.body.email.trim().toLowerCase() : '';
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    // Additional validation beyond schema validation
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    // Check for existing email with case-insensitive search
    const existingEmail = await Email.findOne({ email: email });
    if (existingEmail) {
      return res.status(409).json({ error: 'This email is already subscribed' });
    }

    // Create and save new email
    const newEmail = new Email({ email });
    await newEmail.save();

    res.status(201).json({ message: 'Successfully subscribed to newsletter!' });
  } catch (error) {
    if (error.name === 'ValidationError') {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    console.error('Error saving email:', error);
    res.status(500).json({ error: 'Server error, please try again later' });
  }
});

// Add to collection endpoint - protected with JWT
app.post('/api/add-to-collection', authenticateJWT, async (req, res) => {
  const productName = typeof req.body.productName === 'string' ? req.body.productName.trim() : '';
  const size = typeof req.body.size === 'string' ? req.body.size.trim() : '';

  if (!productName || !size) {
    return res.status(400).json({ success: false, message: 'Product name and size are required' });
  }

  try {
    // Sanitize the query for MongoDB
    const query = sanitizeMongoQuery({ product_code: productName });
    const product = await Product.findOne(query);

    if (product) {
      res.json({ success: true, product, size });
    } else {
      res.status(404).json({ success: false, message: 'Product not found' });
    }
  } catch (err) {
    console.error('Error fetching product:', err);
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Modified checkout endpoint - protected with JWT
app.post('/api/checkout', authenticateJWT, async (req, res) => {
  const { cart, address } = req.body;

  // Input validation
  if (!cart || !Array.isArray(cart) || cart.length === 0) {
    return res.status(400).json({ success: false, message: 'Invalid request. Cart items are required.' });
  }
  
  if (!address || typeof address !== 'object') {
    return res.status(400).json({ success: false, message: 'Invalid request. Address details are required.' });
  }

  try {
    // Extract and validate product codes
    const productCodes = cart.map(item => {
      if (typeof item.productCode !== 'string' || !item.productCode.trim()) {
        throw new Error('Invalid product code in cart');
      }
      return item.productCode.trim();
    });
    
    // Sanitize the MongoDB query
    const query = sanitizeMongoQuery({ product_code: { $in: productCodes } });
    const products = await Product.find(query);

    if (!products || products.length === 0) {
      return res.status(404).json({ success: false, message: 'No products found in database' });
    }

    const enhancedCart = cart.map(cartItem => {
      // Find the corresponding product and validate it exists
      const productData = products.find(p => p.product_code === cartItem.productCode);
      if (!productData) return null;

      // Validate size is a string
      const size = typeof cartItem.size === 'string' ? cartItem.size.trim() : '';
      if (!size) return null;

      return {
        _id: productData._id,
        productCode: productData.product_code,
        productName: productData.product_name,
        price: productData.product_price,
        imageUrl: productData.product_imageurl,
        size: size
      };
    }).filter(Boolean);

    // If all items were invalid, return error
    if (enhancedCart.length === 0) {
      return res.status(400).json({ success: false, message: 'No valid items in cart' });
    }

    // Calculate totals with validation for numeric values
    const subtotal = enhancedCart.reduce((sum, item) => {
      const price = typeof item.price === 'number' && !isNaN(item.price) ? item.price : 0;
      return sum + price;
    }, 0);
    
    const discount = parseFloat((subtotal * 0.1).toFixed(2));
    const delivery = subtotal > 700 ? 0 : 150;
    const total = parseFloat((subtotal + delivery - discount).toFixed(2));

    // Create the order summary with validated data
    const orderSummary = {
      cart: enhancedCart,
      address,  // Already sanitized by middleware
      pricing: { subtotal, discount, delivery, total },
      orderDate: new Date(),
      status: 'pending'
    };

    // Generate a hash of the order data
    const orderHash = generateOrderHash(orderSummary);

    res.status(200).json({ 
      success: true, 
      order: orderSummary,
      orderHash: orderHash
    });
  } catch (err) {
    console.error('Error processing checkout:', err);
    res.status(500).json({ success: false, message: 'Server error processing order', error: err.message });
  }
});

// Modified save-order endpoint - protected with JWT
app.post('/api/save-order', authenticateJWT, async (req, res) => {
  try {
    const { order, orderHash } = req.body;
    
    if (!order || !orderHash || typeof orderHash !== 'string') {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid order data or missing hash' 
      });
    }
    
    // Validate order has required properties
    if (!order.cart || !Array.isArray(order.cart) || !order.address || !order.pricing) {
      return res.status(400).json({
        success: false,
        message: 'Order is missing required fields'
      });
    }
    
    // Verify the hash to ensure data integrity
    if (!verifyOrderHash(order, orderHash)) {
      console.error('Hash verification failed');
      return res.status(400).json({ 
        success: false, 
        message: 'Order verification failed. The order data may have been tampered with.' 
      });
    }
    
    // If hash verification passes, save the order
    const newOrder = new Order(order);
    await newOrder.save();
    
    res.status(200).json({ 
      success: true, 
      message: 'Order saved successfully', 
      orderId: newOrder._id 
    });
  } catch (err) {
    console.error('Error saving order:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error saving order', 
      error: err.message 
    });
  }
});

// Health check endpoint - we'll leave this public
app.get('/api/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  
  res.json({ 
    status: 'ok', 
    database: dbStatus,
    usingAtlas: isUsingAtlas
  });
});

// Apply error handling middleware
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
