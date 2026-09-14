/**
 * Database Service
 * Connects to MongoDB with graceful fallback to in-memory storage
 * when MongoDB is unavailable (development/demo mode).
 */

const mongoose = require('mongoose');

let isConnected = false;
let useInMemory = false;

// In-memory storage fallback
const inMemoryStore = {
  scans: [],
  findings: [],
  audits: [],
};

async function connectDB() {
  const uri = process.env.MONGODB_URI;

  if (!uri) {
    console.log('⚠️  MONGODB_URI not set — using in-memory storage');
    useInMemory = true;
    return;
  }

  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000,
    });
    isConnected = true;
    console.log('✅ Connected to MongoDB');
  } catch (err) {
    console.log('⚠️  MongoDB unavailable — using in-memory storage');
    console.log(`   Reason: ${err.message}`);
    useInMemory = true;
  }
}

function isDBConnected() {
  return isConnected && !useInMemory;
}

function getInMemoryStore() {
  return inMemoryStore;
}

module.exports = { connectDB, isDBConnected, getInMemoryStore };
