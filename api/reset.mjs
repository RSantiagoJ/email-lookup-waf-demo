// Reset endpoint — POST /reset
//
// Zeroes the demo counters so each run starts clean. Does NOT touch the student
// directory (that stays seeded).
//
// Runtime: nodejs22.x
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const STATS_TABLE = process.env.STATS_TABLE;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

export const handler = async (event) => {
  const method = event?.requestContext?.http?.method ?? event?.httpMethod;
  if (method === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }

  await ddb.send(
    new PutCommand({
      TableName: STATS_TABLE,
      Item: { id: "counters", requests: 0, emailsFound: 0, blocked: 0 },
    }),
  );

  return {
    statusCode: 200,
    headers: corsHeaders,
    body: JSON.stringify({ ok: true }),
  };
};
