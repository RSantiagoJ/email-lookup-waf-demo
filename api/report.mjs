// Attack self-report endpoint — POST /report
//
// A WAF block happens at the EDGE: those requests never reach the backend, so the
// normal Stats counters (which only count lookups that hit Lambda) can't see them.
// The load-test / attack script posts how many of its requests the edge rejected
// (its real 403/429 tally) here, so the ops dashboard and the AI triage feed can
// surface the blocks. In production the same number comes from WAF's CloudWatch
// BlockedRequests metric — here the load generator reports it for an instant signal.
//
// Body: { blocked, harvested }   (blocked is recorded; harvested is informational)
// Runtime: nodejs22.x
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";

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

  let body = {};
  try {
    body = event?.body ? JSON.parse(event.body) : {};
  } catch {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: "Body must be a JSON object" }),
    };
  }

  const blocked = Math.max(0, Math.floor(Number(body.blocked) || 0));

  await ddb.send(
    new UpdateCommand({
      TableName: STATS_TABLE,
      Key: { id: "counters" },
      UpdateExpression: "SET blockedAt = :t ADD blocked :b",
      ExpressionAttributeValues: { ":b": blocked, ":t": Date.now() },
    }),
  );

  return {
    statusCode: 200,
    headers: corsHeaders,
    body: JSON.stringify({ ok: true, blocked }),
  };
};
