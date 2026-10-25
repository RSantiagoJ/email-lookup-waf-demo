// WAF control endpoint — GET /waf (status) + POST /waf { on: bool }
//
// Lets the security dashboard toggle ACTUALLY associate / disassociate the web ACL
// with the API Gateway stage (the real "shield on / off"), and report the live
// association state so the UI can show an honest "arming…" indicator.
//
// Note: AssociateWebACL returns as soon as the association record is created, but
// WAF rule ENFORCEMENT takes ~30-60s to propagate across the edge. So "associated"
// = attached; the dashboard still warns that blocking ramps up over the next minute.
//
// Runtime: nodejs22.x
import {
  WAFV2Client,
  AssociateWebACLCommand,
  DisassociateWebACLCommand,
  ListResourcesForWebACLCommand,
} from "@aws-sdk/client-wafv2";

const waf = new WAFV2Client({});
const WEBACL_ARN = process.env.WEBACL_ARN;
const STAGE_ARN = process.env.STAGE_ARN;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

const json = (statusCode, obj) => ({
  statusCode,
  headers: corsHeaders,
  body: JSON.stringify(obj),
});

// Is OUR web ACL currently attached to the API stage? Query from the ACL side
// (ListResourcesForWebACL) rather than the resource side (GetWebACLForResource) —
// the resource-side view lags badly for API Gateway and can report "not attached"
// for up to a minute after an association actually succeeds.
const isAssociated = async () => {
  try {
    const out = await waf.send(
      new ListResourcesForWebACLCommand({
        WebACLArn: WEBACL_ARN,
        ResourceType: "API_GATEWAY",
      }),
    );
    return (out.ResourceArns ?? []).includes(STAGE_ARN);
  } catch {
    return false;
  }
};

export const handler = async (event) => {
  const method = event?.requestContext?.http?.method ?? event?.httpMethod;
  if (method === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }

  if (method === "GET") {
    return json(200, { associated: await isAssociated() });
  }

  // POST { on: true | false }
  let body = {};
  try {
    body = event?.body ? JSON.parse(event.body) : {};
  } catch {
    return json(400, { error: "Body must be a JSON object" });
  }
  const on = Boolean(body.on);

  try {
    if (on) {
      await waf.send(
        new AssociateWebACLCommand({
          WebACLArn: WEBACL_ARN,
          ResourceArn: STAGE_ARN,
        }),
      );
    } else {
      try {
        await waf.send(
          new DisassociateWebACLCommand({ ResourceArn: STAGE_ARN }),
        );
      } catch (e) {
        // Already disassociated is a no-op, not an error.
        if (e?.name !== "WAFNonexistentItemException") throw e;
      }
    }
  } catch (e) {
    return json(500, { error: String(e?.message ?? e), requested: on });
  }

  return json(200, { requested: on, associated: await isAssociated() });
};
