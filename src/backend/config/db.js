const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
require('dotenv').config();
const neo4j = require('neo4j-driver');

const uri = process.env.NEO4J_URI;
const user = process.env.NEO4J_USER || process.env.NEO4J_USERNAME;
const password = process.env.NEO4J_PASSWORD;
const database = process.env.NEO4J_DATABASE;

const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));

// Automatically bind configured database (e.g. for Neo4j Aura cloud instances)
const rawSession = driver.session.bind(driver);
driver.session = function (options = {}) {
  const sessionConfig = { ...options };
  if (database && !sessionConfig.database) {
    sessionConfig.database = database;
  }
  return rawSession(sessionConfig);
};

async function verifyConnection() {
  try {
    const serverInfo = await driver.getServerInfo();
    console.log(`[neo4j] connected to ${serverInfo.agent || 'Neo4j'} at ${serverInfo.address}`);
    if (database) {
      console.log(`[neo4j] active database: ${database}`);
    }
  } catch (err) {
    console.error('[neo4j] connection failed:', err.message);
    console.error('Check NEO4J_URI / NEO4J_USER (or NEO4J_USERNAME) / NEO4J_PASSWORD in your .env');
  }
}

async function closeDriver() {
  await driver.close();
}

module.exports = { driver, verifyConnection, closeDriver };
