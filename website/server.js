const express = require('express');
const path = require('path');
const fs = require('fs');
const { marked } = require('marked');
const hljs = require('highlight.js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const expressLayouts = require('express-ejs-layouts');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for rate limiting
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Compression and static files
app.use(compression());
app.use(express.static(path.join(__dirname, 'public')));

// Set EJS as template engine with layouts
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// Configure marked with syntax highlighting
marked.setOptions({
  highlight: function(code, lang) {
    if (lang && hljs.getLanguage(lang)) {
      try {
        return hljs.highlight(code, { language: lang }).value;
      } catch (__) {}
    }
    return hljs.highlightAuto(code).value;
  },
  breaks: true,
  gfm: true
});

// Helper function to load and parse markdown
function loadMarkdown(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return marked(content);
  } catch (error) {
    console.error(`Error loading markdown file ${filePath}:`, error);
    return '<p>Content not available</p>';
  }
}

// Routes
app.get('/', (req, res) => {
  res.render('index', {
    title: 'Squawk DNS - Secure DNS-over-HTTPS System',
    page: 'home'
  });
});

app.get('/features', (req, res) => {
  res.render('features', {
    title: 'Features - Squawk DNS',
    page: 'features'
  });
});

app.get('/documentation', (req, res) => {
  const releaseNotes = loadMarkdown(path.join(__dirname, '../docs/RELEASE_NOTES.md'));
  res.render('documentation', {
    title: 'Documentation - Squawk DNS',
    page: 'documentation',
    releaseNotes
  });
});

app.get('/pricing', (req, res) => {
  res.render('pricing', {
    title: 'Pricing - Squawk DNS',
    page: 'pricing'
  });
});

app.get('/enterprise', (req, res) => {
  res.render('enterprise', {
    title: 'Enterprise Solutions - Squawk DNS',
    page: 'enterprise'
  });
});

app.get('/download', (req, res) => {
  res.render('download', {
    title: 'Download - Squawk DNS',
    page: 'download'
  });
});

app.get('/contact', (req, res) => {
  res.render('contact', {
    title: 'Contact - Squawk DNS',
    page: 'contact'
  });
});

// API endpoint for release info
app.get('/api/version', (req, res) => {
  try {
    const version = fs.readFileSync(path.join(__dirname, '../.version'), 'utf8').trim();
    res.json({
      version: version,
      releaseDate: new Date().toISOString(),
      downloadUrls: {
        goClient: `https://github.com/penguincloud/squawk/releases/download/${version}-client/`,
        server: `https://github.com/penguincloud/squawk/releases/download/${version}-server/`
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Version information not available' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('404', {
    title: '404 - Page Not Found - Squawk DNS',
    page: '404'
  });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('Server error:', error);
  res.status(500).render('500', {
    title: '500 - Server Error - Squawk DNS',
    page: '500'
  });
});

app.listen(PORT, () => {
  console.log(`Squawk DNS website running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT}`);
});

module.exports = app;