import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  Stack,
  StackProps,
  Duration,
  RemovalPolicy,
  CfnOutput,
  CustomResource,
} from "aws-cdk-lib";
import { Construct } from "constructs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import * as logs from "aws-cdk-lib/aws-logs";
import * as iam from "aws-cdk-lib/aws-iam";

const here = dirname(fileURLToPath(import.meta.url));
const API_DIR = join(here, "../../api"); // email-lookup-waf-demo/api

// The Bedrock model the analyst Lambda invokes. Override with BEDROCK_MODEL_ID at
// deploy time to match whatever you enabled under Bedrock -> Model access. A cross-
// region inference profile id (starts with "us.") is the usual on-demand form.
const BEDROCK_MODEL_ID =
  process.env.BEDROCK_MODEL_ID ?? "us.amazon.nova-micro-v1:0";

export class EmailDemoStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // --- Data ----------------------------------------------------------
    const studentsTable = new dynamodb.Table(this, "StudentsTable", {
      partitionKey: { name: "id", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const statsTable = new dynamodb.Table(this, "StatsTable", {
      partitionKey: { name: "id", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const commonEnv = {
      STUDENTS_TABLE: studentsTable.tableName,
      STATS_TABLE: statsTable.tableName,
    };
    const apiCode = lambda.Code.fromAsset(API_DIR);
    const mkFn = (name: string, handler: string, env: Record<string, string> = {}) =>
      new lambda.Function(this, name, {
        runtime: lambda.Runtime.NODEJS_22_X,
        handler,
        code: apiCode,
        environment: { ...commonEnv, ...env },
        timeout: Duration.seconds(15),
        memorySize: 256,
      });

    // --- Functions -----------------------------------------------------
    const lookupFn = mkFn("LookupFn", "lookup.handler");
    const statsFn = mkFn("StatsFn", "stats.handler");
    const resetFn = mkFn("ResetFn", "reset.handler");
    const reportFn = mkFn("ReportFn", "report.handler");
    const seedFn = mkFn("SeedFn", "seed.handler");
    const analystFn = mkFn("AnalystFn", "analyst.handler", {
      BEDROCK_MODEL_ID,
      // Direct Anthropic Claude API (preferred provider — see analyst.mjs). The key is
      // read from the deploy shell so it never lands in source or chat; leave it unset
      // to build/test on the offline fallback, then set it and redeploy to go live.
      ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY ?? "",
      ANTHROPIC_MODEL: process.env.ANTHROPIC_MODEL ?? "claude-haiku-5-5",
    });

    studentsTable.grantReadData(lookupFn);
    statsTable.grantReadWriteData(lookupFn);
    statsTable.grantReadData(statsFn);
    statsTable.grantReadWriteData(resetFn);
    statsTable.grantReadWriteData(reportFn);
    studentsTable.grantWriteData(seedFn);
    statsTable.grantReadWriteData(seedFn);

    // The analyst Lambda may invoke Bedrock foundation models / inference profiles.
    analystFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["bedrock:InvokeModel"],
        resources: [
          `arn:aws:bedrock:*::foundation-model/*`,
          `arn:aws:bedrock:*:${this.account}:inference-profile/*`,
        ],
      }),
    );

    // Load the fake directory on deploy (re-runs when the version property changes).
    new CustomResource(this, "SeedStudents", {
      serviceToken: seedFn.functionArn,
      properties: { version: Date.now().toString() },
    });

    // --- REST API (WAF attaches to a REST API stage) -------------------
    const api = new apigateway.RestApi(this, "Api", {
      restApiName: "email-lookup-waf-demo",
      deployOptions: {
        stageName: "prod",
        // Always-on API Gateway burst throttle (a token bucket), independent of the WAF
        // shield. This is the control that stops a FAST scrape on the spot (429) — where
        // the WAF rate rule's ~1-min window lets the first burst overshoot. Dashboard
        // polling stays well under this; only the attack bursts hit the ceiling.
        throttlingRateLimit: 10, // steady-state requests/sec
        throttlingBurstLimit: 20, // max instantaneous burst
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
      },
    });
    api.root
      .addResource("email-lookup")
      .addMethod("POST", new apigateway.LambdaIntegration(lookupFn));
    api.root
      .addResource("stats")
      .addMethod("GET", new apigateway.LambdaIntegration(statsFn));
    api.root
      .addResource("reset")
      .addMethod("POST", new apigateway.LambdaIntegration(resetFn));
    api.root
      .addResource("report")
      .addMethod("POST", new apigateway.LambdaIntegration(reportFn));
    api.root
      .addResource("analyst")
      .addMethod("POST", new apigateway.LambdaIntegration(analystFn));

    // --- Attack simulator ----------------------------------------------
    // The dashboard "launch attack" buttons POST here. This Lambda fires REAL requests
    // at the public endpoint from a stable source (itself), so each attack is genuinely
    // evaluated by the WAF — and different attack types trip different rules. Kept as a
    // thin catalog (see api/attack.mjs) so the dashboard can grow into an AWS playground.
    const attackFn = new lambda.Function(this, "AttackFn", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "attack.handler",
      code: apiCode,
      environment: {
        ...commonEnv,
        // Built from restApiId (not api.url) to avoid a Lambda->Stage->Deployment cycle.
        API_BASE: `https://${api.restApiId}.execute-api.${this.region}.amazonaws.com/prod`,
      },
      timeout: Duration.seconds(60),
      memorySize: 256,
    });
    api.root
      .addResource("attack")
      .addMethod("POST", new apigateway.LambdaIntegration(attackFn));

    // --- WAF web ACL (REGIONAL) ----------------------------------------
    // Deliberately NOT associated at deploy: the demo starts UNPROTECTED, then the
    // waf-on script associates this ACL with the API stage live during the pitch.
    const managed = (
      name: string,
      priority: number,
      vendorName: string,
    ): wafv2.CfnWebACL.RuleProperty => ({
      name,
      priority,
      overrideAction: { none: {} },
      statement: {
        managedRuleGroupStatement: { vendorName: "AWS", name: vendorName },
      },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: name,
      },
    });

    const webAcl = new wafv2.CfnWebACL(this, "WebAcl", {
      name: "email-lookup-waf-demo",
      scope: "REGIONAL",
      defaultAction: { allow: {} },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: "email-lookup-waf-demo",
      },
      rules: [
        // The hero: rate limit 100 req / 5 min, aggregated by IP + User-Agent
        // (mirrors prod's "rate-limit-apis-by-ip-useragent" rule). A single client
        // hammering the directory trips the limit and gets blocked at the edge.
        {
          name: "RateLimit",
          priority: 0,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              limit: 100,
              aggregateKeyType: "CUSTOM_KEYS",
              customKeys: [
                { ip: {} },
                {
                  header: {
                    name: "User-Agent",
                    textTransformations: [{ priority: 0, type: "NONE" }],
                  },
                },
              ],
            },
          },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: "RateLimit",
          },
        },
        managed("SQLi", 1, "AWSManagedRulesSQLiRuleSet"),
        managed("CommonRuleSet", 2, "AWSManagedRulesCommonRuleSet"),
        managed("KnownBadInputs", 3, "AWSManagedRulesKnownBadInputsRuleSet"),
        managed("IpReputation", 4, "AWSManagedRulesAmazonIpReputationList"),
      ],
    });

    // WAF logs -> CloudWatch (log group name MUST start with aws-waf-logs-).
    const wafLogGroup = new logs.LogGroup(this, "WafLogGroup", {
      logGroupName: "aws-waf-logs-email-demo",
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    new wafv2.CfnLoggingConfiguration(this, "WafLogging", {
      resourceArn: webAcl.attrArn,
      logDestinationConfigs: [wafLogGroup.logGroupArn],
    });

    // ARN of the API stage, for the waf-on / waf-off association scripts and the
    // WAF-control Lambda. Built from the literal stage name ("prod", set in
    // deployOptions) rather than api.deploymentStage so the control Lambda does NOT
    // depend on the Stage resource — referencing the stage object here creates a
    // circular dependency (Lambda -> Stage -> Deployment -> /waf methods -> Lambda).
    const stageArn = `arn:aws:apigateway:${this.region}::/restapis/${api.restApiId}/stages/prod`;

    // --- WAF control endpoint ------------------------------------------
    // Lets the dashboard toggle ACTUALLY associate / disassociate the web ACL
    // with the API stage (the real shield), and report the live association
    // state so the UI can show an honest "arming…" indicator.
    const wafFn = mkFn("WafControlFn", "waf.handler", {
      WEBACL_ARN: webAcl.attrArn,
      STAGE_ARN: stageArn,
    });
    wafFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "wafv2:ListResourcesForWebACL",
        ],
        resources: ["*"],
      }),
    );
    wafFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["apigateway:SetWebACL"],
        resources: [stageArn],
      }),
    );
    const wafResource = api.root.addResource("waf");
    wafResource.addMethod("GET", new apigateway.LambdaIntegration(wafFn));
    wafResource.addMethod("POST", new apigateway.LambdaIntegration(wafFn));

    // --- Real WAF proof endpoint ---------------------------------------
    // Returns ACTUAL blocked requests sampled by AWS WAF (GetSampledRequests), so the
    // dashboard can prove the blocks are real AWS decisions, not a mock.
    const wafSamplesFn = mkFn("WafSamplesFn", "wafsamples.handler", {
      WEBACL_ARN: webAcl.attrArn,
    });
    wafSamplesFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["wafv2:GetSampledRequests"],
        resources: ["*"],
      }),
    );
    api.root
      .addResource("waf-samples")
      .addMethod("GET", new apigateway.LambdaIntegration(wafSamplesFn));

    // --- Outputs -------------------------------------------------------
    new CfnOutput(this, "ApiUrl", { value: api.url });
    new CfnOutput(this, "WebAclArn", { value: webAcl.attrArn });
    new CfnOutput(this, "ApiStageArn", { value: stageArn });
    new CfnOutput(this, "WafLogGroupName", { value: wafLogGroup.logGroupName });
    new CfnOutput(this, "StudentsTableName", { value: studentsTable.tableName });
    new CfnOutput(this, "StatsTableName", { value: statsTable.tableName });
    new CfnOutput(this, "BedrockModelId", { value: BEDROCK_MODEL_ID });
  }
}
