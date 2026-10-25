// Stats endpoint — GET /stats
//
// Returns the live demo counters for the security dashboard. Cheap and pollable
// (the dashboard hits this every ~2s).
//
// Response: { requests, emailsFound, blocked, directorySize, updatedAt }
//
// Runtime: nodejs22.x
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const STATS_TABLE = process.env.STATS_TABLE;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

const DIRECTORY_SIZE = 50; // fake students seeded (see data/generate-seed.mjs)

export const handler = async (event) => {
  const method = event?.requestContext?.http?.method ?? event?.httpMethod;
  if (method === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }

  const out = await ddb.send(
    new GetCommand({ TableName: STATS_TABLE, Key: { id: "counters" } }),
  );
  const c = out.Item ?? {};

  return {
    statusCode: 200,
    headers: corsHeaders,
    body: JSON.stringify({
      requests: Number(c.requests ?? 0),
      emailsFound: Number(c.emailsFound ?? 0),
      blocked: Number(c.blocked ?? 0),
      directorySize: DIRECTORY_SIZE,
      updatedAt: Date.now(),
    }),
  };
};
