import dotenv from "dotenv";
dotenv.config();

import { MongoClient, ServerApiVersion } from "mongodb";

// Single shared MongoClient for both better-auth and application queries.
// Previously auth.js and index.js each created their own MongoClient,
// doubling connection usage — a real problem on Vercel serverless where
// every cold start would open 2× connections against Atlas.
const client = new MongoClient(process.env.MONGO_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const db = client.db("dispo");

export { client, db };
