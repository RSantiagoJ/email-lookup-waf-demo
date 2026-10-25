// Seed handler — CloudFormation custom resource (runs on each deploy).
//
// Loads the bundled fake directory (students.json) into the Students table and
// initializes the Stats counters. Responds to CloudFormation directly via the
// pre-signed ResponseURL (this is wired as a bare Lambda-backed CustomResource).
//
// Runtime: nodejs22.x
import { readFileSync } from "node:fs";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  BatchWriteCommand,
  PutCommand,
} from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const STUDENTS_TABLE = process.env.STUDENTS_TABLE;
const STATS_TABLE = process.env.STATS_TABLE;

// Tell CloudFormation whether the custom resource succeeded.
const respond = async (event, status, reason) => {
  const body = JSON.stringify({
    Status: status,
    Reason: reason ?? "See CloudWatch logs",
    PhysicalResourceId: "email-demo-seed",
    StackId: event.StackId,
    RequestId: event.RequestId,
    LogicalResourceId: event.LogicalResourceId,
    Data: {},
  });
  await fetch(event.ResponseURL, {
    method: "PUT",
    headers: { "content-type": "", "content-length": String(body.length) },
    body,
  });
};

const seedDirectory = async () => {
  const students = JSON.parse(
    readFileSync(new URL("./students.json", import.meta.url), "utf8"),
  );
  // BatchWrite in chunks of 25 (DynamoDB limit).
  for (let i = 0; i < students.length; i += 25) {
    const chunk = students.slice(i, i + 25);
    await ddb.send(
      new BatchWriteCommand({
        RequestItems: {
          [STUDENTS_TABLE]: chunk.map((s) => ({ PutRequest: { Item: s } })),
        },
      }),
    );
  }
  // Fresh counters.
  await ddb.send(
    new PutCommand({
      TableName: STATS_TABLE,
      Item: { id: "counters", requests: 0, emailsFound: 0 },
    }),
  );
  return students.length;
};

export const handler = async (event) => {
  try {
    if (event.RequestType === "Delete") {
      // Tables are destroyed with the stack; nothing to undo here.
      await respond(event, "SUCCESS", "Delete no-op");
      return;
    }
    const n = await seedDirectory();
    await respond(event, "SUCCESS", `Seeded ${n} fake students`);
  } catch (err) {
    console.error(err);
    await respond(event, "FAILED", String(err?.message ?? err));
  }
};
