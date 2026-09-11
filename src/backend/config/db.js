require('dotenv').config();
const neo4j = require('neo4j-driver');

const driver = neo4j.driver(
  process.env.NEO4J_URI,
  neo4j.auth.basic(process.env.NEO4J_USER, process.env.NEO4J_PASSWORD)
);

async function verifyConnection() {
  try {
    await driver.verifyConnectivity();
    console.log('[neo4j] connected');
  } catch (err) {
    console.error('[neo4j] connection failed:', err.message);
    console.error('Check NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD in your .env');
  }
}

async function closeDriver() {
  await driver.close();
}

module.exports = { driver, verifyConnection, closeDriver };
