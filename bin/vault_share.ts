#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib/core';
import { VaultShareStack } from '../lib/vault_share-stack';

const app = new cdk.App();
new VaultShareStack(app, 'VaultShareStack', {

  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },

});
