require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { verifyConnection } = require('./config/db');
const graphRoutes = require('./routes/graph');

const app = express();

const corsOrigin = process.env.CORS_ORIGIN || '*';
app.use(
  cors({
    origin: corsOrigin === '*' ? '*' : corsOrigin.split(',').map((o) => o.trim()),
    credentials: true,
  })
);

app.use(express.json());

// Health check endpoint for Render and uptime monitors
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'zenith-backend',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

app.use('/api', graphRoutes);

const frontendDist = path.resolve(__dirname, '../frontend/dist');

app.get('/', (req, res) => {
  const indexPath = path.join(frontendDist, 'index.html');
  const landingPath = path.join(frontendDist, 'landing-page/index.html');

  if (fs.existsSync(indexPath) && req.query.console === 'true') {
    return res.sendFile(indexPath);
  }
  if (fs.existsSync(landingPath)) {
    return res.redirect('/landing-page/index.html');
  }

  return res.json({
    service: 'ZENITH Attack Path Intelligence API',
    status: 'online',
    version: '1.0.0',
    documentation: '/api/relationship-types',
    health: '/health',
  });
});

if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
}

// Keep direct links to the React console working after a browser refresh if static bundle is present
app.get('*', (req, res, next) => {
  const indexPath = path.join(frontendDist, 'index.html');
  if (req.accepts('html') && fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  return next();
});

const PORT = process.env.PORT || 4000;

verifyConnection().then(() => {
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
});
