#!/bin/bash

# Satoru Upload - Complete Ubuntu Auto Setup & Deployment Script
# Version: 2.0.0 (Ubuntu Production Ready)
# Author: Centus on Satoru Team
# Usage: curl -s https://raw.githubusercontent.com/tieubao9k/Satoru-Team-Public/refs/heads/main/setup.sh | bash

set -e

clear
echo "🌟 Satoru Upload - Complete Auto Setup & Deployment (Ubuntu)"
echo "============================================================="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ This script should not be run as root${NC}"
   echo "Please run as a regular user with sudo privileges"
   exit 1
fi

echo -e "${BLUE}🔧 Configuration Setup${NC}"
echo "======================="
echo ""

read -p "Enter your domain name (e.g., upload.yourdomain.com): " DOMAIN
while [[ -z "$DOMAIN" ]]; do
    echo -e "${RED}Domain is required!${NC}"
    read -p "Enter your domain name: " DOMAIN
done

read -p "Enter email for SSL certificate (Let's Encrypt): " SSL_EMAIL
while [[ -z "$SSL_EMAIL" ]]; do
    echo -e "${RED}Email is required for SSL!${NC}"
    read -p "Enter email for SSL certificate: " SSL_EMAIL
done

read -p "Service port (default: 3000): " SERVICE_PORT
SERVICE_PORT=${SERVICE_PORT:-3000}

read -p "Service user (default: satoru): " SERVICE_USER
SERVICE_USER=${SERVICE_USER:-satoru}

API_KEY="satoru-$(openssl rand -hex 16)"

echo ""
echo -e "${BLUE}📋 Configuration Summary${NC}"
echo "========================"
echo "• Domain: $DOMAIN"
echo "• SSL Email: $SSL_EMAIL"
echo "• Service Port: $SERVICE_PORT"
echo "• Service User: $SERVICE_USER"
echo "• API Key: $API_KEY"
echo ""

read -p "Continue with installation? (y/N): " CONFIRM
if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
    echo "Installation cancelled"
    exit 0
fi

echo -e "${BLUE}📦 Updating system and installing dependencies...${NC}"
sudo apt update -y
sudo apt upgrade -y
sudo apt install -y curl wget git build-essential ufw nginx certbot python3-certbot-nginx

if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}⚠️  Installing Node.js...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    echo -e "${GREEN}✅ Node.js installed: $(node --version)${NC}"
else
    echo -e "${GREEN}✅ Node.js found: $(node --version)${NC}"
fi

echo -e "${BLUE}👤 Creating service user: ${SERVICE_USER}${NC}"
if ! id "$SERVICE_USER" &>/dev/null; then
    sudo useradd -r -s /bin/bash -d /opt/satoru-upload -m $SERVICE_USER
    echo -e "${GREEN}✅ User ${SERVICE_USER} created${NC}"
else
    echo -e "${YELLOW}⚠️  User ${SERVICE_USER} already exists${NC}"
fi

PROJECT_DIR="/opt/satoru-upload"
echo -e "${BLUE}📁 Creating project directory: ${PROJECT_DIR}${NC}"

if [ -d "$PROJECT_DIR" ]; then
    echo -e "${YELLOW}⚠️  Directory exists. Backing up...${NC}"
    sudo mv "$PROJECT_DIR" "${PROJECT_DIR}.backup.$(date +%s)"
fi

sudo mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

echo -e "${BLUE}📂 Creating folder structure...${NC}"
sudo mkdir -p routes middleware public uploads data logs

echo -e "${BLUE}📦 Creating package.json...${NC}"
sudo tee package.json > /dev/null << 'EOF'
{
  "name": "satoru-upload",
  "version": "2.0.0",
  "description": "Satoru Upload - Professional File Upload API Service with Short Links",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "node test.js",
    "ubuntu": "node server.js",
    "pm2": "pm2 start ecosystem.config.js",
    "pm2:stop": "pm2 stop satoru-upload",
    "pm2:restart": "pm2 restart satoru-upload"
  },
  "keywords": ["satoru-upload", "file-upload", "api", "nodejs", "express", "ubuntu", "short-links"],
  "author": "Satoru Upload Team",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "multer": "^1.4.5-lts.1",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.8.1",
    "uuid": "^9.0.0",
    "moment": "^2.29.4",
    "dotenv": "^16.3.1",
    "fs-extra": "^11.1.1",
    "mime-types": "^2.1.35",
    "winston": "^3.10.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "pm2": "^5.3.0"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
EOF

# Create .env
echo -e "${BLUE}⚙️ Creating .env configuration...${NC}"
sudo tee .env > /dev/null << EOF
# Server Configuration
PORT=$SERVICE_PORT
HOST=0.0.0.0
NODE_ENV=production

# Domain Configuration
DOMAIN=$DOMAIN
SSL_EMAIL=$SSL_EMAIL

# Security & Authentication
API_KEY=$API_KEY
ALLOWED_ORIGINS=*

# Upload Configuration
MAX_FILE_SIZE=104857600
ALLOWED_FILE_TYPES=*

# Storage
UPLOAD_DIR=uploads
DATA_DIR=data
LOG_DIR=logs

# Rate Limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=1000
UPLOAD_RATE_LIMIT_WINDOW=60000
UPLOAD_RATE_LIMIT_MAX=100

# Logging
LOG_LEVEL=info
LOG_MAX_SIZE=10m
LOG_MAX_FILES=5

# Service Configuration
SERVICE_USER=$SERVICE_USER
PROJECT_DIR=$PROJECT_DIR
EOF

echo -e "${BLUE}🚫 Creating .gitignore...${NC}"
sudo tee .gitignore > /dev/null << 'EOF'
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env.local
.env.development.local
.env.test.local
.env.production.local

# Uploads
uploads/*
!uploads/.gitkeep

# Data
data/*.json
!data/.gitkeep

# Logs
logs/*
!logs/.gitkeep

# Runtime data
pids/
*.pid
*.seed
*.pid.lock

# Operating System
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
*.swo

# PM2
.pm2/

# Temporary files
tmp/
temp/
EOF

echo -e "${BLUE}🖥️ Creating server.js...${NC}"
sudo tee server.js > /dev/null << 'EOF'
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs-extra');
const winston = require('winston');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'satoru-upload' },
  transports: [
    new winston.transports.File({ 
      filename: path.join(process.env.LOG_DIR || 'logs', 'error.log'), 
      level: 'error',
      maxsize: process.env.LOG_MAX_SIZE || '10m',
      maxFiles: process.env.LOG_MAX_FILES || 5
    }),
    new winston.transports.File({ 
      filename: path.join(process.env.LOG_DIR || 'logs', 'combined.log'),
      maxsize: process.env.LOG_MAX_SIZE || '10m',
      maxFiles: process.env.LOG_MAX_FILES || 5
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS === '*' ? true : process.env.ALLOWED_ORIGINS?.split(','),
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.set('trust proxy', 1);

app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });
  next();
});

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 1000,
  message: {
    success: false,
    message: 'Too many requests, please try again later.'
  },
  onLimitReached: (req) => {
    logger.warn('Rate limit reached', { ip: req.ip });
  }
});

const uploadLimiter = rateLimit({
  windowMs: parseInt(process.env.UPLOAD_RATE_LIMIT_WINDOW) || 60 * 1000,
  max: parseInt(process.env.UPLOAD_RATE_LIMIT_MAX) || 100,
  message: {
    success: false,
    message: 'Too many uploads, please try again later.'
  },
  onLimitReached: (req) => {
    logger.warn('Upload rate limit reached', { ip: req.ip });
  }
});

app.use(limiter);

app.use(express.static('public'));

app.use(express.static('uploads', {
  maxAge: '1y',
  etag: true,
  lastModified: true
}));

fs.ensureDirSync('uploads');
fs.ensureDirSync('data');
fs.ensureDirSync('logs');

const filesPath = path.join(__dirname, 'data', 'files.json');
if (!fs.existsSync(filesPath)) {
  fs.writeJsonSync(filesPath, []);
}

app.use('/api/upload', uploadLimiter, require('./routes/upload'));
app.use('/api/files', require('./routes/files'));
app.use('/api/delete', require('./routes/delete'));

app.get('/api/health', (req, res) => {
  const healthInfo = {
    success: true,
    message: 'Satoru Upload Server is running',
    service: 'Satoru Upload API',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    platform: 'ubuntu',
    node_version: process.version,
    memory: process.memoryUsage(),
    env: process.env.NODE_ENV,
    domain: process.env.DOMAIN
  };
  
  logger.info('Health check requested', healthInfo);
  res.json(healthInfo);
});

app.get('/api', (req, res) => {
  res.json({
    success: true,
    message: 'Satoru Upload API - File Upload Service',
    service: 'Satoru Upload',
    version: '2.0.0',
    platform: 'Ubuntu Server',
    domain: process.env.DOMAIN,
    endpoints: {
      upload_single: 'POST /api/upload/single',
      upload_multiple: 'POST /api/upload/multiple',
      list_files: 'GET /api/files',
      get_file: 'GET /api/files/:id',
      download_file: 'GET /api/files/download/:id',
      delete_file: 'DELETE /api/delete/:id',
      health: 'GET /api/health'
    },
    authentication: 'API key required in X-API-Key header',
    contact: 'Contact admin for API key access',
    file_access: 'Files are accessible directly: https://domain.com/filename.ext'
  });
});

app.use((req, res) => {
  logger.warn('404 Not Found', { url: req.url, ip: req.ip });
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

app.use((error, req, res, next) => {
  logger.error('Unhandled error', { 
    error: error.message, 
    stack: error.stack,
    url: req.url,
    ip: req.ip 
  });
  
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

function getLocalIP() {
  const { networkInterfaces } = require('os');
  const nets = networkInterfaces();
  
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return 'localhost';
}

const server = app.listen(PORT, HOST, () => {
  const localIP = getLocalIP();
  const startupInfo = {
    message: 'Satoru Upload Server Started',
    port: PORT,
    host: HOST,
    localIP: localIP,
    domain: process.env.DOMAIN,
    env: process.env.NODE_ENV || 'development',
    uploadDir: path.resolve('uploads'),
    timestamp: new Date().toISOString()
  };
  
  logger.info('Server started', startupInfo);
  
  console.log('\n🌟 Satoru Upload Server Started!');
  console.log('=====================================');
  console.log(`📱 Local: http://localhost:${PORT}`);
  console.log(`🌐 Network: http://${localIP}:${PORT}`);
  console.log(`🌍 Domain: https://${process.env.DOMAIN || 'not-configured'}`);
  console.log(`📁 Upload directory: ${path.resolve('uploads')}`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔐 API Key: Required for uploads`);
  console.log(`🔗 File access: Direct links like https://${process.env.DOMAIN || 'domain.com'}/filename.jpg`);
  console.log(`📊 Logs: ${path.resolve('logs')}`);
  console.log('=====================================\n');
});

module.exports = app;
EOF

echo -e "${BLUE}🔧 Creating middleware/upload.js...${NC}"
sudo tee middleware/upload.js > /dev/null << 'EOF'
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs-extra');

const uploadDir = process.env.UPLOAD_DIR || 'uploads';
fs.ensureDirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const tempName = `temp_${Date.now()}_${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, tempName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = process.env.ALLOWED_FILE_TYPES;
  
  if (allowedTypes === '*') {
    const ext = path.extname(file.originalname).toLowerCase().slice(1);
    const dangerousTypes = ['exe', 'bat', 'com', 'cmd', 'scr', 'pif', 'vbs', 'ws', 'wsf', 'wsc', 'wsh', 'ps1', 'msi'];
    
    if (dangerousTypes.includes(ext)) {
      cb(new Error(`File type .${ext} is not allowed for security reasons`), false);
      return;
    }
    
    cb(null, true);
  } else {
    const allowedTypesArray = allowedTypes?.split(',') || [
      'jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt', 'zip', 'rar', 'mp4', 'mp3', 'wav'
    ];
    
    const ext = path.extname(file.originalname).toLowerCase().slice(1);
    
    if (allowedTypesArray.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`File type .${ext} is not allowed. Allowed types: ${allowedTypesArray.join(', ')}`), false);
    }
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 100 * 1024 * 1024, 
    files: 20 
  }
});

module.exports = upload;
EOF

echo -e "${BLUE}🔐 Creating middleware/auth.js...${NC}"
sudo tee middleware/auth.js > /dev/null << 'EOF'
const auth = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.body.api_key || req.query.api_key;
  
  if (!process.env.API_KEY) {
    return res.status(500).json({
      success: false,
      message: 'Server configuration error: API key not set'
    });
  }
  
  if (!apiKey) {
    return res.status(401).json({
      success: false,
      message: 'API key is required. Contact admin to get API key.',
      error_code: 'MISSING_API_KEY'
    });
  }
  
  if (apiKey !== process.env.API_KEY) {
    return res.status(401).json({
      success: false,
      message: 'Invalid API key. Contact admin for valid API key.',
      error_code: 'INVALID_API_KEY'
    });
  }
  
  next();
};

module.exports = auth;
EOF

echo -e "${BLUE}📤 Creating routes/upload.js...${NC}"
sudo tee routes/upload.js > /dev/null << 'EOF'
const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs-extra');
const upload = require('../middleware/upload');
const auth = require('../middleware/auth');
const moment = require('moment');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/upload.log' })
  ]
});

function getServerUrl(req) {
  const protocol = req.secure ? 'https' : 'http';
  const host = req.get('host');
  return `${protocol}://${host}`;
}

router.post('/single', auth, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      logger.warn('Upload attempt without file', { ip: req.ip });
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    const originalName = req.file.originalname;
    const fileExtension = path.extname(originalName);
    const shortName = `${Date.now()}_${Math.random().toString(36).substr(2, 6)}${fileExtension}`;
    
    const oldPath = req.file.path;
    const newPath = path.join('uploads', shortName);
    fs.moveSync(oldPath, newPath);

    const fileInfo = {
      id: require('uuid').v4(),
      original_name: originalName,
      filename: shortName,
      path: newPath,
      size: req.file.size,
      mimetype: req.file.mimetype,
      upload_time: moment().format('YYYY-MM-DD HH:mm:ss'),
      uploaded_by: req.ip
    };

    const filesPath = path.join(__dirname, '../data/files.json');
    const files = fs.readJsonSync(filesPath, { throws: false }) || [];
    files.push(fileInfo);
    fs.writeJsonSync(filesPath, files, { spaces: 2 });

    const serverUrl = getServerUrl(req);
    const directLink = `${serverUrl}/${shortName}`;
    const downloadLink = `${serverUrl}/api/files/download/${fileInfo.id}`;

    logger.info('File uploaded successfully', {
      filename: shortName,
      originalName: originalName,
      size: req.file.size,
      ip: req.ip,
      url: directLink
    });

    res.json({
      success: true,
      message: 'File uploaded successfully',
      url: directLink,
      link: directLink,
      download_url: downloadLink,
      download_link: downloadLink,
      file: {
        id: fileInfo.id,
        original_name: fileInfo.original_name,
        filename: fileInfo.filename,
        size: fileInfo.size,
        mimetype: fileInfo.mimetype,
        upload_time: fileInfo.upload_time
      }
    });

  } catch (error) {
    logger.error('Upload error', { error: error.message, ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Upload failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

router.post('/multiple', auth, upload.array('files', 20), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      logger.warn('Multiple upload attempt without files', { ip: req.ip });
      return res.status(400).json({
        success: false,
        message: 'No files uploaded'
      });
    }

    const serverUrl = getServerUrl(req);
    const uploadedFiles = [];

    req.files.forEach(file => {
      const originalName = file.originalname;
      const fileExtension = path.extname(originalName);
      const shortName = `${Date.now()}_${Math.random().toString(36).substr(2, 6)}${fileExtension}`;
      
      const oldPath = file.path;
      const newPath = path.join('uploads', shortName);
      fs.moveSync(oldPath, newPath);

      const fileInfo = {
        id: require('uuid').v4(),
        original_name: originalName,
        filename: shortName,
        path: newPath,
        size: file.size,
        mimetype: file.mimetype,
        upload_time: moment().format('YYYY-MM-DD HH:mm:ss'),
        uploaded_by: req.ip
      };

      const directLink = `${serverUrl}/${shortName}`;
      const downloadLink = `${serverUrl}/api/files/download/${fileInfo.id}`;

      uploadedFiles.push({
        ...fileInfo,
        url: directLink,
        link: directLink,
        download_url: downloadLink,
        download_link: downloadLink
      });
    });

    const filesPath = path.join(__dirname, '../data/files.json');
    const files = fs.readJsonSync(filesPath, { throws: false }) || [];
    files.push(...uploadedFiles);
    fs.writeJsonSync(filesPath, files, { spaces: 2 });

    logger.info('Multiple files uploaded successfully', {
      count: uploadedFiles.length,
      ip: req.ip,
      files: uploadedFiles.map(f => f.filename)
    });

    res.json({
      success: true,
      message: `${uploadedFiles.length} files uploaded successfully`,
      files: uploadedFiles.map(file => ({
        id: file.id,
        original_name: file.original_name,
        filename: file.filename,
        size: file.size,
        mimetype: file.mimetype,
        upload_time: file.upload_time,
        url: file.url,
        link: file.link,
        download_url: file.download_url,
        download_link: file.download_link
      }))
    });

  } catch (error) {
    logger.error('Multiple upload error', { error: error.message, ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Upload failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

router.use((error, req, res, next) => {
  logger.error('Multer error', { error: error.message, ip: req.ip });
  
  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({
      success: false,
      message: 'File too large. Maximum size: 100MB'
    });
  }
  if (error.code === 'LIMIT_FILE_COUNT') {
    return res.status(400).json({
      success: false,
      message: 'Too many files. Maximum: 20 files'
    });
  }
  
  res.status(400).json({
    success: false,
    message: error.message || 'Upload error'
  });
});

module.exports = router;
EOF

echo -e "${BLUE}📋 Creating routes/files.js...${NC}"
sudo tee routes/files.js > /dev/null << 'EOF'
const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs-extra');
const auth = require('../middleware/auth');

function getServerUrl(req) {
  const protocol = req.secure ? 'https' : 'http';
  const host = req.get('host');
  return `${protocol}://${host}`;
}

router.get('/', auth, (req, res) => {
  try {
    const filesPath = path.join(__dirname, '../data/files.json');
    const files = fs.readJsonSync(filesPath, { throws: false }) || [];
    
    const serverUrl = getServerUrl(req);
    
    const filesWithLinks = files.map(file => ({
      ...file,
      url: `${serverUrl}/${file.filename}`,
      link: `${serverUrl}/${file.filename}`,
      download_url: `${serverUrl}/api/files/download/${file.id}`,
      download_link: `${serverUrl}/api/files/download/${file.id}`
    }));

    res.json({
      success: true,
      files: filesWithLinks.reverse(), // Show newest first
      total: filesWithLinks.length
    });

  } catch (error) {
    console.error('Files list error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get files list',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

router.get('/:id', auth, (req, res) => {
  try {
    const filesPath = path.join(__dirname, '../data/files.json');
    const files = fs.readJsonSync(filesPath, { throws: false }) || [];
    
    const file = files.find(f => f.id === req.params.id);
    
    if (!file) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    const serverUrl = getServerUrl(req);
    
    res.json({
      success: true,
      file: {
        ...file,
        url: `${serverUrl}/${file.filename}`,
        link: `${serverUrl}/${file.filename}`,
        download_url: `${serverUrl}/api/files/download/${file.id}`,
        download_link: `${serverUrl}/api/files/download/${file.id}`
      }
    });

  } catch (error) {
    console.error('Get file error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get file',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

router.get('/download/:id', (req, res) => {
  try {
    const filesPath = path.join(__dirname, '../data/files.json');
    const files = fs.readJsonSync(filesPath, { throws: false }) || [];
    
    const file = files.find(f => f.id === req.params.id);
    
    if (!file || !fs.existsSync(file.path)) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    res.download(file.path, file.original_name);

  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({
      success: false,
      message: 'Download failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;
EOF

echo -e "${BLUE}🗑️ Creating routes/delete.js...${NC}"
sudo tee routes/delete.js > /dev/null << 'EOF'
const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs-extra');
const auth = require('../middleware/auth');

router.delete('/:id', auth, (req, res) => {
  try {
    const filesPath = path.join(__dirname, '../data/files.json');
    const files = fs.readJsonSync(filesPath, { throws: false }) || [];
    
    const fileIndex = files.findIndex(f => f.id === req.params.id);
    
    if (fileIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    const file = files[fileIndex];
    
    if (fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }

    files.splice(fileIndex, 1);
    fs.writeJsonSync(filesPath, files, { spaces: 2 });

    res.json({
      success: true,
      message: 'File deleted successfully'
    });

  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({
      success: false,
      message: 'Delete failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

router.delete('/', auth, (req, res) => {
  try {
    const { filename } = req.body;
    
    if (!filename) {
      return res.status(400).json({
        success: false,
        message: 'Filename is required'
      });
    }

    const filesPath = path.join(__dirname, '../data/files.json');
    const files = fs.readJsonSync(filesPath, { throws: false }) || [];
    
    const fileIndex = files.findIndex(f => 
      f.filename === filename || f.original_name === filename
    );
    
    if (fileIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    const file = files[fileIndex];
    
    if (fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }

    files.splice(fileIndex, 1);
    fs.writeJsonSync(filesPath, files, { spaces: 2 });

    res.json({
      success: true,
      message: 'File deleted successfully'
    });

  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({
      success: false,
      message: 'Delete failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;
EOF

echo -e "${BLUE}🌐 Creating public/index.html...${NC}"
sudo tee public/index.html > /dev/null << 'EOF'
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Satoru Upload</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
            color: white;
        }

        .header h1 {
            font-size: 3.5rem;
            font-weight: 700;
            margin-bottom: 10px;
            text-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }

        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .main-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 24px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
            overflow: hidden;
            border: 1px solid rgba(255,255,255,0.2);
        }

        .nav-tabs {
            display: flex;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-bottom: 1px solid #dee2e6;
        }

        .nav-tab {
            flex: 1;
            padding: 20px;
            text-align: center;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            color: #6c757d;
            transition: all 0.3s ease;
            position: relative;
        }

        .nav-tab:hover {
            color: #667eea;
            background: rgba(102, 126, 234, 0.05);
        }

        .nav-tab.active {
            color: #667eea;
            background: rgba(102, 126, 234, 0.1);
        }

        .nav-tab.active::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 3px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 2px;
        }

        .tab-content {
            display: none;
            padding: 40px;
            animation: fadeIn 0.3s ease;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* API Documentation Styles */
        .api-grid {
            display: grid;
            gap: 20px;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        }

        .api-card {
            background: #f8f9fa;
            border-radius: 16px;
            padding: 24px;
            border: 1px solid #e9ecef;
            transition: all 0.3s ease;
        }

        .api-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 32px rgba(0,0,0,0.1);
        }

        .api-card h3 {
            color: #667eea;
            font-size: 1.3rem;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .method-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            color: white;
        }

        .method-post { background: #28a745; }
        .method-get { background: #007bff; }
        .method-delete { background: #dc3545; }

        .code-snippet {
            background: #2d3748;
            color: #e2e8f0;
            padding: 16px;
            border-radius: 12px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            margin: 12px 0;
            position: relative;
        }

        .copy-btn {
            position: absolute;
            top: 12px;
            right: 12px;
            background: rgba(255,255,255,0.1);
            border: none;
            color: #e2e8f0;
            padding: 6px 10px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.2s ease;
        }

        .copy-btn:hover {
            background: rgba(255,255,255,0.2);
        }

        .auth-banner {
            background: linear-gradient(135deg, #ffeaa7, #fdcb6e);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 8px 24px rgba(253, 203, 110, 0.3);
        }

        .auth-input-group {
            display: flex;
            gap: 12px;
            max-width: 500px;
            margin: 20px auto 0;
        }

        .auth-input {
            flex: 1;
            padding: 12px 16px;
            border: 2px solid #e9ecef;
            border-radius: 12px;
            font-size: 1rem;
            font-family: 'Monaco', monospace;
            transition: border-color 0.3s ease;
        }

        .auth-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(102, 126, 234, 0.4);
        }

        .btn-success {
            background: linear-gradient(135deg, #00b894, #00a085);
            color: white;
        }

        .status-indicator {
            padding: 12px 20px;
            border-radius: 12px;
            margin: 16px 0;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-success {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .status-error {
            background: linear-gradient(135deg, #f8d7da, #f5c6cb);
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .status-warning {
            background: linear-gradient(135deg, #fff3cd, #ffeaa7);
            color: #856404;
            border: 1px solid #ffeaa7;
        }

        .upload-zone {
            border: 3px dashed #cbd5e0;
            border-radius: 20px;
            padding: 60px 40px;
            text-align: center;
            background: linear-gradient(135deg, #f8f9ff, #f1f3ff);
            transition: all 0.3s ease;
            cursor: pointer;
            margin: 30px 0;
        }

        .upload-zone:hover,
        .upload-zone.dragover {
            border-color: #667eea;
            background: linear-gradient(135deg, #e8f0ff, #f0f4ff);
            transform: translateY(-4px);
            box-shadow: 0 12px 32px rgba(102, 126, 234, 0.2);
        }

        .upload-zone.disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }

        .upload-icon {
            font-size: 3rem;
            color: #667eea;
            margin-bottom: 20px;
        }

        .upload-zone h3 {
            font-size: 1.4rem;
            margin-bottom: 8px;
            color: #2d3748;
        }

        .upload-zone p {
            color: #718096;
            font-size: 1rem;
        }

        .progress-container {
            margin: 24px 0;
            display: none;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 8px;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(135deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.3s ease;
        }

        .progress-text {
            text-align: center;
            font-size: 0.9rem;
            color: #6c757d;
        }

        .result-item {
            background: white;
            border-radius: 16px;
            padding: 20px;
            margin: 16px 0;
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
            border-left: 4px solid #28a745;
        }

        .result-item.error {
            border-left-color: #dc3545;
        }

        .result-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
        }

        .result-info {
            font-size: 0.9rem;
            color: #6c757d;
        }

        .link-group {
            display: flex;
            gap: 8px;
            margin: 8px 0;
            align-items: center;
        }

        .link-input {
            flex: 1;
            padding: 8px 12px;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            background: #f8f9fa;
            font-size: 0.9rem;
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 0.8rem;
            border-radius: 6px;
        }

        .alert {
            padding: 16px 20px;
            border-radius: 12px;
            margin: 16px 0;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .alert-success {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .alert-error {
            background: linear-gradient(135deg, #f8d7da, #f5c6cb);
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .highlight {
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
        }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin: 24px 0;
        }

        .feature-item {
            background: linear-gradient(135deg, #f8f9ff, #f1f3ff);
            padding: 16px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid #e9ecef;
        }

        .feature-icon {
            font-size: 2rem;
            color: #667eea;
            margin-bottom: 8px;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .header h1 {
                font-size: 2.5rem;
            }

            .main-card {
                border-radius: 16px;
            }

            .tab-content {
                padding: 20px;
            }

            .api-grid {
                grid-template-columns: 1fr;
            }

            .auth-input-group {
                flex-direction: column;
            }

            .upload-zone {
                padding: 40px 20px;
            }

            .link-group {
                flex-direction: column;
                align-items: stretch;
            }

            .link-input {
                margin-bottom: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-cloud-upload-alt"></i> <span class="highlight">Satoru Upload</span></h1>
            <p>Professional File Upload API Service</p>
        </div>

        <div class="main-card">
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab('docs')">
                    <i class="fas fa-book"></i> API Docs
                </button>
                <button class="nav-tab" onclick="showTab('upload')">
                    <i class="fas fa-upload"></i> Upload Files
                </button>
            </div>

            <!-- API Documentation Tab -->
            <div id="docs-tab" class="tab-content active">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h2>🔐 <span class="highlight">API Authentication Required</span></h2>
                    <p>Liên hệ admin để nhận API key. Thêm header <code>X-API-Key</code> vào tất cả requests.</p>
                    <p><strong>Domain:</strong> <span id="currentDomain">Loading...</span></p>
                </div>

                <div class="api-grid">
                    <div class="api-card">
                        <h3><i class="fas fa-upload"></i> Upload File</h3>
                        <span class="method-badge method-post">POST</span>
                        <code>/api/upload/single</code>
                        
                        <div class="code-snippet">
                            <button class="copy-btn" onclick="copyCode(this)"><i class="fas fa-copy"></i></button>
                            <pre id="upload-example">// Loading domain...</pre>
                        </div>
                    </div>

                    <div class="api-card">
                        <h3><i class="fas fa-list"></i> List Files</h3>
                        <span class="method-badge method-get">GET</span>
                        <code>/api/files</code>
                        
                        <div class="code-snippet">
                            <button class="copy-btn" onclick="copyCode(this)"><i class="fas fa-copy"></i></button>
                            <pre id="files-example">// Loading domain...</pre>
                        </div>
                    </div>

                    <div class="api-card">
                        <h3><i class="fas fa-download"></i> Download File</h3>
                        <span class="method-badge method-get">GET</span>
                        <code>/filename.ext</code>
                        
                        <div class="code-snippet">
                            <button class="copy-btn" onclick="copyCode(this)"><i class="fas fa-copy"></i></button>
                            <pre id="download-example">// Loading domain...</pre>
                        </div>
                    </div>

                    <div class="api-card">
                        <h3><i class="fas fa-trash"></i> Delete File</h3>
                        <span class="method-badge method-delete">DELETE</span>
                        <code>/api/delete/:id</code>
                        
                        <div class="code-snippet">
                            <button class="copy-btn" onclick="copyCode(this)"><i class="fas fa-copy"></i></button>
                            <pre id="delete-example">// Loading domain...</pre>
                        </div>
                    </div>
                </div>

                <div class="feature-grid" style="margin-top: 40px;">
                    <div class="feature-item">
                        <div class="feature-icon"><i class="fas fa-shield-alt"></i></div>
                        <strong>100MB Max</strong>
                        <p>File size limit</p>
                    </div>
                    <div class="feature-item">
                        <div class="feature-icon"><i class="fas fa-file"></i></div>
                        <strong>All Types</strong>
                        <p>Supported formats</p>
                    </div>
                    <div class="feature-item">
                        <div class="feature-icon"><i class="fas fa-link"></i></div>
                        <strong>Short Links</strong>
                        <p>domain.com/file.jpg</p>
                    </div>
                    <div class="feature-item">
                        <div class="feature-icon"><i class="fas fa-tachometer-alt"></i></div>
                        <strong>1000/15min</strong>
                        <p>Rate limit</p>
                    </div>
                </div>
            </div>

            <!-- Upload Files Tab -->
            <div id="upload-tab" class="tab-content">
                <div class="auth-banner">
                    <h3><i class="fas fa-key"></i> API Key Authentication</h3>
                    <p>Nhập API key để bắt đầu upload files</p>
                    
                    <div class="auth-input-group">
                        <input type="password" id="apiKeyInput" class="auth-input" placeholder="Nhập API key của bạn...">
                        <button class="btn btn-success" onclick="saveApiKey()">
                            <i class="fas fa-check"></i> Xác thực
                        </button>
                    </div>
                </div>

                <div id="authStatus" class="status-indicator status-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    Chưa có API Key. Liên hệ admin để nhận API key.
                </div>

                <div class="upload-zone disabled" id="uploadZone">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <h3>Kéo thả files vào đây</h3>
                    <p>hoặc click để chọn files (tối đa 100MB)</p>
                    <input type="file" id="fileInput" multiple style="display: none;">
                    <div style="margin-top: 20px;">
                        <button class="btn btn-primary" onclick="document.getElementById('fileInput').click()">
                            <i class="fas fa-folder-open"></i> Chọn Files
                        </button>
                    </div>
                </div>

                <div class="progress-container" id="progressContainer">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                    <div class="progress-text" id="progressText">Uploading...</div>
                </div>

                <div id="uploadResults"></div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/axios/1.4.0/axios.min.js"></script>
    <script>
        let selectedFiles = [];
        let apiKey = localStorage.getItem('satoru_api_key') || '';
        let currentDomain = window.location.host;

        document.addEventListener('DOMContentLoaded', function() {
            setupEventListeners();
            checkApiKey();
            checkServerConnection();
            updateDomainInfo();
        });

        function updateDomainInfo() {
            document.getElementById('currentDomain').textContent = currentDomain;
            
            const protocol = window.location.protocol;
            const baseUrl = `${protocol}//${currentDomain}`;
            
            document.getElementById('upload-example').textContent = `const formData = new FormData();
formData.append('file', file);

axios.post('${baseUrl}/api/upload/single', formData, {
  headers: {
    'X-API-Key': 'your-api-key'
  }
}).then(res => {
  console.log('Short URL:', res.data.url);
  // Result: "${baseUrl}/1720234567_a1b2c3.jpg"
});`;

            document.getElementById('files-example').textContent = `axios.get('${baseUrl}/api/files', {
  headers: {
    'X-API-Key': 'your-api-key'
  }
}).then(res => {
  console.log('Files:', res.data.files);
});`;

            document.getElementById('download-example').textContent = `// Direct access (no API key needed)
window.open('${baseUrl}/1720234567_a1b2c3.jpg');

// Or download with original name
window.open('${baseUrl}/api/files/download/file-id');`;

            document.getElementById('delete-example').textContent = `axios.delete('${baseUrl}/api/delete/file-id', {
  headers: {
    'X-API-Key': 'your-api-key'
  }
}).then(res => {
  console.log('Deleted:', res.data.message);
});`;
        }

        function setupEventListeners() {
            const fileInput = document.getElementById('fileInput');
            const uploadZone = document.getElementById('uploadZone');

            fileInput.addEventListener('change', e => handleFiles(e.target.files));

            uploadZone.addEventListener('dragover', e => {
                e.preventDefault();
                if (apiKey) uploadZone.classList.add('dragover');
            });

            uploadZone.addEventListener('dragleave', e => {
                e.preventDefault();
                uploadZone.classList.remove('dragover');
            });

            uploadZone.addEventListener('drop', e => {
                e.preventDefault();
                uploadZone.classList.remove('dragover');
                if (apiKey) handleFiles(e.dataTransfer.files);
            });

            uploadZone.addEventListener('click', () => {
                if (apiKey) fileInput.click();
            });

            if (apiKey) {
                document.getElementById('apiKeyInput').value = apiKey;
                updateAuthStatus('success', 'API Key đã lưu. Ready to upload!');
                enableUpload();
            }
        }

        function showTab(tabName) {
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            const activeTab = tabName === 'docs' ? 0 : 1;
            document.querySelectorAll('.nav-tab')[activeTab].classList.add('active');
            document.getElementById(`${tabName}-tab`).classList.add('active');
        }

        async function saveApiKey() {
            const input = document.getElementById('apiKeyInput');
            const newApiKey = input.value.trim();
            
            if (!newApiKey) {
                updateAuthStatus('error', 'Vui lòng nhập API key.');
                return;
            }
            
            updateAuthStatus('warning', 'Đang kiểm tra API key...');
            
            try {
                await axios.get('/api/files', {
                    headers: { 'X-API-Key': newApiKey }
                });
                
                apiKey = newApiKey;
                localStorage.setItem('satoru_api_key', apiKey);
                updateAuthStatus('success', 'API Key hợp lệ! Ready to upload!');
                enableUpload();
            } catch (error) {
                updateAuthStatus('error', 'API key không hợp lệ. Vui lòng kiểm tra lại.');
                disableUpload();
            }
        }

        function updateAuthStatus(type, message) {
            const status = document.getElementById('authStatus');
            status.className = `status-indicator status-${type}`;
            
            const icons = {
                success: 'fas fa-check-circle',
                error: 'fas fa-times-circle',
                warning: 'fas fa-exclamation-triangle'
            };
            
            status.innerHTML = `<i class="${icons[type]}"></i> ${message}`;
        }

        function enableUpload() {
            const uploadZone = document.getElementById('uploadZone');
            uploadZone.classList.remove('disabled');
        }

        function disableUpload() {
            const uploadZone = document.getElementById('uploadZone');
            uploadZone.classList.add('disabled');
        }

        function checkApiKey() {
            if (!apiKey) {
                updateAuthStatus('warning', 'Chưa có API Key. Vui lòng nhập API key để upload files.');
                disableUpload();
            }
        }

        async function checkServerConnection() {
            try {
                const response = await axios.get('/api/health');
                if (response.data.success) {
                    showAlert('success', 'Kết nối Satoru Upload thành công!');
                }
            } catch (error) {
                showAlert('error', 'Không thể kết nối server');
            }
        }

        function handleFiles(files) {
            if (!apiKey) {
                showAlert('error', 'Vui lòng nhập API key trước khi upload');
                return;
            }
            
            selectedFiles = Array.from(files);
            if (selectedFiles.length > 0) uploadFiles();
        }

        async function uploadFiles() {
            const progressContainer = document.getElementById('progressContainer');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            const uploadResults = document.getElementById('uploadResults');

            uploadResults.innerHTML = '';
            progressContainer.style.display = 'block';
            progressFill.style.width = '0%';

            try {
                if (selectedFiles.length === 1) {
                    const formData = new FormData();
                    formData.append('file', selectedFiles[0]);
                    
                    progressText.textContent = `Đang upload ${selectedFiles[0].name}...`;

                    const response = await axios.post('/api/upload/single', formData, {
                        headers: { 'X-API-Key': apiKey, 'Content-Type': 'multipart/form-data' }
                    });

                    progressFill.style.width = '100%';
                    
                    if (response.data.success) {
                        showUploadResult(response.data.file, response.data.url, response.data.download_url, true);
                    }
                } else {
                    const formData = new FormData();
                    selectedFiles.forEach(file => formData.append('files', file));
                    
                    progressText.textContent = `Đang upload ${selectedFiles.length} files...`;

                    const response = await axios.post('/api/upload/multiple', formData, {
                        headers: { 'X-API-Key': apiKey, 'Content-Type': 'multipart/form-data' }
                    });

                    progressFill.style.width = '100%';
                    
                    if (response.data.success && response.data.files) {
                        response.data.files.forEach(file => {
                            showUploadResult(file, file.url, file.download_url, true);
                        });
                    }
                }
            } catch (error) {
                if (error.response?.status === 401) {
                    showUploadResult({ original_name: 'Upload' }, null, null, false, 'API key không hợp lệ');
                    apiKey = '';
                    localStorage.removeItem('satoru_api_key');
                    updateAuthStatus('error', 'API key hết hạn. Vui lòng nhập lại.');
                    disableUpload();
                } else {
                    showUploadResult({ original_name: 'Upload' }, null, null, false, error.response?.data?.message || error.message);
                }
            } finally {
                setTimeout(() => {
                    progressContainer.style.display = 'none';
                    progressFill.style.width = '0%';
                }, 2000);

                document.getElementById('fileInput').value = '';
                selectedFiles = [];
            }
        }

        function showUploadResult(file, url, downloadUrl, success, errorMessage = '') {
            const uploadResults = document.getElementById('uploadResults');
            const resultDiv = document.createElement('div');
            resultDiv.className = `result-item ${success ? '' : 'error'}`;

            if (success) {
                resultDiv.innerHTML = `
                    <div class="result-header">
                        <i class="fas fa-check-circle" style="color: #28a745; font-size: 1.2rem;"></i>
                        <strong>${file.original_name}</strong>
                        <span class="result-info">${formatFileSize(file.size)} • ${file.mimetype}</span>
                    </div>
                    <div class="link-group">
                        <input type="text" class="link-input" value="${url}" readonly>
                        <button class="btn btn-sm btn-success" onclick="copyToClipboard('${url}')">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                        <a href="${url}" target="_blank" class="btn btn-sm btn-primary">
                            <i class="fas fa-external-link-alt"></i> Open
                        </a>
                    </div>
                    <div class="link-group">
                        <input type="text" class="link-input" value="${downloadUrl}" readonly>
                        <button class="btn btn-sm btn-success" onclick="copyToClipboard('${downloadUrl}')">
                            <i class="fas fa-download"></i> Copy Download
                        </button>
                        <a href="${downloadUrl}" target="_blank" class="btn btn-sm btn-primary">
                            <i class="fas fa-download"></i> Download
                        </a>
                    </div>
                `;
            } else {
                resultDiv.innerHTML = `
                    <div class="result-header">
                        <i class="fas fa-times-circle" style="color: #dc3545; font-size: 1.2rem;"></i>
                        <strong>${file.original_name}</strong>
                    </div>
                    <div style="color: #dc3545; margin-top: 8px;">${errorMessage}</div>
                `;
            }

            uploadResults.appendChild(resultDiv);
        }

        function copyToClipboard(text) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    showAlert('success', 'Link đã copy vào clipboard!');
                }).catch(() => {
                    fallbackCopyToClipboard(text);
                });
            } else {
                fallbackCopyToClipboard(text);
            }
        }

        function fallbackCopyToClipboard(text) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.opacity = '0';
            document.body.appendChild(textArea);
            textArea.select();
            
            try {
                document.execCommand('copy');
                showAlert('success', 'Link đã copy vào clipboard!');
            } catch (err) {
                showAlert('error', 'Không thể copy link');
            }
            
            document.body.removeChild(textArea);
        }

        function showAlert(type, message) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type}`;
            
            const icons = {
                success: 'fas fa-check-circle',
                error: 'fas fa-times-circle'
            };
            
            alertDiv.innerHTML = `<i class="${icons[type]}"></i> ${message}`;
            
            document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.main-card'));
            
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.parentNode.removeChild(alertDiv);
                }
            }, 4000);
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function copyCode(button) {
            const codeBlock = button.nextElementSibling;
            const text = codeBlock.textContent;
            
            copyToClipboard(text);
            
            const originalIcon = button.innerHTML;
            button.innerHTML = '<i class="fas fa-check"></i>';
            setTimeout(() => {
                button.innerHTML = originalIcon;
            }, 1000);
        }
    </script>
</body>
</html>
EOF

sudo touch uploads/.gitkeep
sudo touch data/.gitkeep
sudo touch logs/.gitkeep

echo -e "${BLUE}⚙️ Creating systemd service...${NC}"
sudo tee /etc/systemd/system/satoru-upload.service > /dev/null << EOF
[Unit]
Description=Satoru Upload - File Upload API Service
Documentation=https://github.com/satoru-upload/satoru-upload
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${PROJECT_DIR}
Environment=NODE_ENV=production
Environment=PORT=${SERVICE_PORT}
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=satoru-upload

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${PROJECT_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

echo -e "${BLUE}⚙️ Creating PM2 ecosystem...${NC}"
sudo tee ecosystem.config.js > /dev/null << EOF
module.exports = {
  apps: [{
    name: 'satoru-upload',
    script: 'server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'development',
      PORT: ${SERVICE_PORT}
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: ${SERVICE_PORT}
    },
    error_file: 'logs/pm2-error.log',
    out_file: 'logs/pm2-out.log',
    log_file: 'logs/pm2-combined.log',
    time: true,
    max_memory_restart: '1G',
    watch: false,
    ignore_watch: ['node_modules', 'uploads', 'logs'],
    restart_delay: 4000
  }]
}
EOF

echo -e "${BLUE}📦 Installing Node.js dependencies...${NC}"
sudo npm install --production

echo -e "${BLUE}📦 Installing PM2...${NC}"
sudo npm install -g pm2

echo -e "${BLUE}🔒 Setting permissions...${NC}"
sudo chown -R $SERVICE_USER:$SERVICE_USER "$PROJECT_DIR"
sudo chmod -R 755 "$PROJECT_DIR"
sudo chmod 600 "$PROJECT_DIR/.env"

echo -e "${BLUE}🌐 Configuring nginx reverse proxy...${NC}"
sudo tee /etc/nginx/sites-available/satoru-upload > /dev/null << EOF
server {
    listen 80;
    server_name ${DOMAIN};
    
    client_max_body_size 100M;
    
    location / {
        proxy_pass http://localhost:${SERVICE_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 86400;
    }
    
    # Direct file serving for better performance
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|pdf|zip|rar|mp4|mp3|wav)$ {
        proxy_pass http://localhost:${SERVICE_PORT};
        expires 1y;
        add_header Cache-Control "public, immutable";
        add_header X-Served-By "Satoru Upload";
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/satoru-upload /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

if sudo nginx -t; then
    echo -e "${GREEN}✅ Nginx configuration is valid${NC}"
else
    echo -e "${RED}❌ Nginx configuration error${NC}"
    exit 1
fi

echo -e "${BLUE}🔥 Configuring firewall...${NC}"
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

echo -e "${BLUE}🚀 Starting services...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable satoru-upload
sudo systemctl start satoru-upload
sudo systemctl restart nginx

sleep 5

if sudo systemctl is-active --quiet satoru-upload; then
    echo -e "${GREEN}✅ Satoru Upload service is running${NC}"
else
    echo -e "${RED}❌ Failed to start Satoru Upload service${NC}"
    sudo systemctl status satoru-upload --no-pager
    exit 1
fi

echo -e "${BLUE}🔒 Installing SSL certificate...${NC}"
if sudo certbot --nginx -d "$DOMAIN" --email "$SSL_EMAIL" --agree-tos --non-interactive --redirect; then
    echo -e "${GREEN}✅ SSL certificate installed successfully${NC}"
else
    echo -e "${YELLOW}⚠️  SSL installation failed. You can retry later with:${NC}"
    echo "sudo certbot --nginx -d $DOMAIN --email $SSL_EMAIL"
fi

echo -e "${BLUE}🔧 Creating management scripts...${NC}"

sudo tee "${PROJECT_DIR}/start.sh" > /dev/null << 'EOF'
#!/bin/bash
echo "🌟 Starting Satoru Upload Server..."
sudo systemctl start satoru-upload
sudo systemctl status satoru-upload --no-pager
EOF

sudo tee "${PROJECT_DIR}/stop.sh" > /dev/null << 'EOF'
#!/bin/bash
echo "🛑 Stopping Satoru Upload Server..."
sudo systemctl stop satoru-upload
echo "✅ Satoru Upload stopped"
EOF

sudo tee "${PROJECT_DIR}/restart.sh" > /dev/null << 'EOF'
#!/bin/bash
echo "🔄 Restarting Satoru Upload Server..."
sudo systemctl restart satoru-upload
sudo systemctl status satoru-upload --no-pager
EOF

sudo tee "${PROJECT_DIR}/logs.sh" > /dev/null << 'EOF'
#!/bin/bash
echo "📋 Satoru Upload Logs (Press Ctrl+C to exit)"
echo "============================================"
sudo journalctl -u satoru-upload -f
EOF

sudo tee "${PROJECT_DIR}/update.sh" > /dev/null << 'EOF'
#!/bin/bash
echo "🔄 Updating Satoru Upload..."
cd /opt/satoru-upload
sudo systemctl stop satoru-upload

# Backup current version
sudo tar -czf "/tmp/satoru-backup-$(date +%s).tar.gz" --exclude=node_modules .

# Update dependencies
sudo -u satoru npm install --production

# Restart service
sudo systemctl start satoru-upload
echo "✅ Update completed"
EOF

sudo tee "${PROJECT_DIR}/backup.sh" > /dev/null << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/satoru-upload-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "💾 Creating Satoru Upload backup..."
sudo mkdir -p "$BACKUP_DIR"
sudo tar -czf "$BACKUP_DIR/satoru-upload-$TIMESTAMP.tar.gz" \
  --exclude=node_modules \
  --exclude=logs \
  /opt/satoru-upload

echo "✅ Backup created: $BACKUP_DIR/satoru-upload-$TIMESTAMP.tar.gz"
EOF

sudo chmod +x "${PROJECT_DIR}"/*.sh

echo -e "${BLUE}📖 Creating README.md...${NC}"
sudo tee README.md > /dev/null << EOF
# 🌟 Satoru Upload - Ubuntu Production Setup

Satoru Upload đã được cài đặt và cấu hình hoàn chỉnh trên Ubuntu Server.

## 🔧 Thông tin cài đặt

- **Domain:** https://$DOMAIN
- **API Key:** $API_KEY
- **Service Port:** $SERVICE_PORT
- **Service User:** $SERVICE_USER
- **Project Directory:** $PROJECT_DIR

## 🚀 Truy cập

- **Website:** https://$DOMAIN
- **API Endpoint:** https://$DOMAIN/api
- **Health Check:** https://$DOMAIN/api/health

## 🔐 API Usage

### Upload file
\`\`\`bash
curl -X POST \\
  -H "X-API-Key: $API_KEY" \\
  -F "file=@image.jpg" \\
  https://$DOMAIN/api/upload/single
\`\`\`

### List files
\`\`\`bash
curl -H "X-API-Key: $API_KEY" https://$DOMAIN/api/files
\`\`\`

### Direct file access
\`\`\`
https://$DOMAIN/filename.jpg
\`\`\`

## 🔧 Management Commands

\`\`\`bash
# Service management
sudo systemctl start satoru-upload
sudo systemctl stop satoru-upload
sudo systemctl restart satoru-upload
sudo systemctl status satoru-upload

# View logs
sudo journalctl -u satoru-upload -f

# Quick scripts
cd $PROJECT_DIR
./start.sh    # Start service
./stop.sh     # Stop service
./restart.sh  # Restart service
./logs.sh     # View logs
./backup.sh   # Create backup
./update.sh   # Update application
\`\`\`

## 📁 Directory Structure

\`\`\`
$PROJECT_DIR/
├── server.js           # Main application
├── package.json        # Dependencies
├── .env               # Configuration
├── routes/            # API routes
├── middleware/        # Express middleware
├── public/            # Web interface
├── uploads/           # Uploaded files
├── data/              # JSON database
├── logs/              # Application logs
└── *.sh              # Management scripts
\`\`\`

## 🔒 Security

- ✅ Firewall configured (UFW)
- ✅ SSL certificate installed
- ✅ API key authentication
- ✅ Rate limiting enabled
- ✅ File type validation
- ✅ Nginx reverse proxy

## 📊 Monitoring

\`\`\`bash
# Check service status
sudo systemctl status satoru-upload

# Check nginx status  
sudo systemctl status nginx

# View error logs
sudo tail -f $PROJECT_DIR/logs/error.log

# Check disk usage
df -h $PROJECT_DIR

# Check memory usage
free -h
\`\`\`

## 🆘 Troubleshooting

### Service won't start
\`\`\`bash
sudo systemctl status satoru-upload
sudo journalctl -u satoru-upload -n 50
\`\`\`

### SSL issues
\`\`\`bash
sudo certbot renew --dry-run
sudo nginx -t
\`\`\`

### Port conflicts
\`\`\`bash
sudo netstat -tulpn | grep :$SERVICE_PORT
\`\`\`

### Reset API key
\`\`\`bash
cd $PROJECT_DIR
sudo nano .env  # Edit API_KEY
sudo systemctl restart satoru-upload
\`\`\`

## 📞 Support

- **Service Status:** https://$DOMAIN/api/health
- **Logs Location:** $PROJECT_DIR/logs/
- **Config File:** $PROJECT_DIR/.env
- **Backup Location:** /opt/satoru-upload-backups/

---
**🌟 Satoru Upload** - Production ready file upload service
Installed on: $(date)
EOF

# Final setup completion
echo ""
echo -e "${GREEN}🌟 Satoru Upload Ubuntu Setup Completed Successfully!${NC}"
echo "=============================================================="
echo ""
echo -e "${BLUE}🌍 Access Information:${NC}"
echo "• Website: https://$DOMAIN"
echo "• API: https://$DOMAIN/api"
echo "• Health Check: https://$DOMAIN/api/health"
echo ""
echo -e "${BLUE}🔐 Security Information:${NC}"
echo "• API Key: $API_KEY"
echo "• SSL: Enabled with Let's Encrypt"
echo "• Firewall: Configured and active"
echo ""
echo -e "${BLUE}🔧 Management:${NC}"
echo "• Start: sudo systemctl start satoru-upload"
echo "• Stop: sudo systemctl stop satoru-upload"
echo "• Restart: sudo systemctl restart satoru-upload"
echo "• Logs: sudo journalctl -u satoru-upload -f"
echo "• Config: $PROJECT_DIR/.env"
echo ""
echo -e "${BLUE}📱 Quick Test:${NC}"
echo "curl -H \"X-API-Key: $API_KEY\" https://$DOMAIN/api/health"
echo ""
echo -e "${BLUE}📋 Next Steps:${NC}"
echo "1. Point your DNS A record to this server's IP"
echo "2. Wait for DNS propagation (1-24 hours)"
echo "3. Test file upload via web interface"
echo "4. Share the API key with authorized users"
echo "5. Configure regular backups if needed"
echo ""
echo -e "${GREEN}✅ Ready for production use!${NC}"
echo -e "${BLUE}🌟 Visit: https://$DOMAIN${NC}"
