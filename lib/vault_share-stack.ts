import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Effect } from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambdaNode from 'aws-cdk-lib/aws-lambda-nodejs';
import * as lambda from 'aws-cdk-lib/aws-lambda';




// import * as sqs from 'aws-cdk-lib/aws-sqs';

export class VaultShareStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    
    const filesKey = new kms.Key(this, 'FilesKey', {
      alias:'alias/vaultshare-files',
      description: 'Encrypts VaultShare user files at rest',
      enableKeyRotation:true,
      removalPolicy: cdk.RemovalPolicy.DESTROY, 
      pendingWindow: cdk.Duration.days(7)
    })

    const filesBucket = new s3.Bucket(this, 'FilesBucket',{
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned:true,
      minimumTLSVersion: 1.2,  
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      enforceSSL: true,
      encryption: s3.BucketEncryption.KMS, // encryption scheme teh bucket uses by default for every object written to it.
      encryptionKey: filesKey,
      bucketKeyEnabled: true,    
    })

    const filesFnRole = new iam.Role(this, 'FilesFnRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Execution role for the VaultShare files API',
      managedPolicies: [
        // AWS-MANAGED: off-the-shelf CloudWatch Logs access. Correct choice
        // here — it's a generic concern AWS maintains and versions.
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AWSLambdaBasicExecutionRole',
        ),
      ],
    });
    
    const filesFn = new lambdaNode.NodejsFunction(this, 'FilesFn', {
      entry: 'lambda/files/index.ts',
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_20_X,
      role: filesFnRole,
      timeout: cdk.Duration.seconds(10),
      environment: {
        BUCKET_NAME: filesBucket.bucketName,
        KEY_ARN: filesKey.keyArn,
      },
    });

    //bucket level policy 
    filesFnRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['s3:ListBucket'],
      resources: [filesBucket.bucketArn],
    }));

    //objet level policy
    filesFnRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
      resources: [filesBucket.arnForObjects('*')], // object-level
    }))

    //needed S# forwards tehcaller's identity to KMS.
    //GenerateDataKey = upload. Decrypt = download.
    filesFnRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
      resources: [filesKey.keyArn],
      conditions:{
        StringEquals: { 'kms:ViaService': `s3.${this.region}.amazonaws.com` },
      }
    }))

    //Ressource-based policy - the KMS Key. 
    filesKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowFilesFnEnvelopeEncryption',
      effect: iam.Effect.ALLOW,
      principals: [filesFnRole],
      actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
      resources: ['*'],
    }))

    //Outputs
    new cdk.CfnOutput(this, 'BucketName', { value: filesBucket.bucketName})
    new cdk.CfnOutput(this, 'KeyArn', { value: filesKey.keyArn })
    new cdk.CfnOutput(this, 'FunctionName', {value: filesFn.functionName });
    new cdk.CfnOutput(this, 'RoleArn', {value: filesFnRole.roleArn})    
  }
}
