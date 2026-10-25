#!/usr/bin/env node
import { App } from "aws-cdk-lib";
import { EmailDemoStack } from "../lib/email-demo-stack.js";

const app = new App();
new EmailDemoStack(app, "EmailLookupWafDemo", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? "us-east-1",
  },
  description:
    "Innovation sprint demo: AWS WAF + Bedrock shielding a public student email-lookup API (fake data).",
});
