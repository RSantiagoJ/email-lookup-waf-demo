// Real WAF proof — GET /waf-samples
//
// Pulls ACTUAL sampled requests from AWS WAF (GetSampledRequests) for this web ACL over
// the last 10 minutes and returns the BLOCKED ones, so the dashboard can prove the blocks
// are real AWS WAF decisions — not a mock. GetSampledRequests takes a per-rule metric, so
// we query each rule and merge. Free (WAF API read); WAF samples a subset of requests.
//
// Runtime: nodejs22.x
import {
  WAFV2Client,
  GetSampledRequestsCommand,
} from "@aws-sdk/client-wafv2";

const client = new WAFV2Client({});
const WEBACL_ARN = process.env.WEBACL_ARN;

// The rule metric names set in the CDK stack (one per rule in the web ACL).
const RULE_METRICS = [
  "RateLimit",
  "SQLi",
  "CommonRuleSet",
  "KnownBadInputs",
  "IpReputation",
];

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

  const EndTime = new Date();
  const StartTime = new Date(EndTime.getTime() - 10 * 60 * 1000); // last 10 min

  try {
    const perRule = await Promise.all(
      RULE_METRICS.map(async (metric) => {
        try {
          const out = await client.send(
            new GetSampledRequestsCommand({
              WebAclArn: WEBACL_ARN,
              RuleMetricName: metric,
              Scope: "REGIONAL",
              TimeWindow: { StartTime, EndTime },
              MaxItems: 50,
            }),
          );
          return (out.SampledRequests ?? []).map((s) => ({ s, metric }));
        } catch {
          return []; // a rule with no samples in-window can 404; ignore it
        }
      }),
    );

    const samples = perRule
      .flat()
      .filter(({ s }) => s.Action === "BLOCK")
      .sort(
        (a, b) =>
          new Date(b.s.Timestamp ?? 0).getTime() -
          new Date(a.s.Timestamp ?? 0).getTime(),
      )
      .slice(0, 25)
      .map(({ s, metric }) => ({
        ip: s.Request?.ClientIP ?? "",
        uri: s.Request?.URI ?? "",
        method: s.Request?.Method ?? "",
        rule: metric,
        at: s.Timestamp ? new Date(s.Timestamp).toISOString() : null,
      }));

    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({ samples, count: samples.length }),
    };
  } catch (err) {
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({ samples: [], error: String(err?.message ?? err) }),
    };
  }
};
