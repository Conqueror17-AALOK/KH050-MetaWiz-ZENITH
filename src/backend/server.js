require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { verifyConnection } = require('./config/db');
const graphRoutes = require('./routes/graph');

const app = express();
app.use(cors());
app.use(express.json());

app.use('/api', graphRoutes);

app.get('/', (req, res) => {
  res.send('PS17 Attack Path Analyzer API is running');
});

const PORT = process.env.PORT || 4000;

verifyConnection().then(() => {
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
});
