import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Effect } from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambdaNode from 'aws-cdk-lib/aws-lambda-nodejs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as apigwv2int from 'aws-cdk-lib/aws-apigatewayv2-integrations';

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

    const reportsRole = new iam.Role(this, 'ReportsReaderRole',{
      roleName: 'VaultShareReportsReader',
      assumedBy: new iam.ArnPrincipal(`arn:aws:iam::${this.account}:user/yahya-dev`),  //trust policy
      description: 'Assumable role for reading reports - STS demo',
      maxSessionDuration: cdk.Duration.hours(1),
    })

    reportsRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['s3:GetObject'],
      resources: [filesBucket.arnForObjects('reports/*')]
    }))

    reportsRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['kms:Decrypt'],
      resources: [filesKey.keyArn],
    }))

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

    //user pool -> auth only and issues jwts
    const userPool = new cognito.UserPool(this, 'VaultShareUserPool', {
      userPoolName: 'vaultshare-users',
      selfSignUpEnabled: true,// allows users to register themselves via the sign-up page
      signInAliases: {email: true},//feilds users can use to sign in
      autoVerify: {email: true},
      standardAttributes: { //schema
        email: { required: true, mutable: false },
      },
      passwordPolicy: {
        minLength: 12,
        // Password must contain at least one lowercase letter.
        requireLowercase: true,

        // Password must contain at least one uppercase letter.
        requireUppercase: true,

        // Password must contain at least one digit (0-9).
        requireDigits: true,

        // Password must contain at least one symbol (!@#$ etc.).
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    })

    const userPoolClient = new cognito.UserPoolClient(this, 'VaultShareWebClient', {
      userPool,
      userPoolClientName: 'vaultshare-web',
      generateSecret:false,
      authFlows: {
        userPassword: true,   // needed for CLI testing
        userSrp: true,        // what a real frontend uses
      },
      accessTokenValidity: cdk.Duration.hours(1),
      idTokenValidity: cdk.Duration.hours(1),
      refreshTokenValidity: cdk.Duration.days(30),
    })

    const identityPool = new cognito.CfnIdentityPool(this, 'VaultShareIdentityPool', {
      identityPoolName: 'vaultshare_identities',
      allowUnauthenticatedIdentities: false,// no guest access
      cognitoIdentityProviders: [{
        clientId: userPoolClient.userPoolClientId,
        providerName: userPool.userPoolProviderName,
        serverSideTokenCheck: true,//verify user still exist and not signed out.
      }],
    })

    const authenticatedRole = new iam.Role(this, 'CognitoAuthenticatedRole', {
      roleName: 'VaultShareAuthenticatedUser',
      description: 'Assumed by authenticated Cognito users',
      assumedBy: new iam.FederatedPrincipal(
        'cognito-identity.amazonaws.com',
        {

          StringEquals: {
            'cognito-identity.amazonaws.com:aud': identityPool.ref,
          },
          'ForAnyValue:StringLike': {
            'cognito-identity.amazonaws.com:amr': 'authenticated',
          },
        },
        'sts:AssumeRoleWithWebIdentity',   // NOT sts:AssumeRole
      )
    })

    //verifies jwt in code, then acts on thealler's behalf.
    const apiFnRole = new iam.Role(this, 'ApiFnRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Execution role for the VaultShare API',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AWSLambdaBasicExecutionRole'),
      ],
    })

    apiFnRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['s3:ListBucket'],
      resources: [filesBucket.bucketArn],
    }))

    const apiFn = new lambdaNode.NodejsFunction(this, 'ApiFn', {
      entry: 'lambda/api/index.ts',
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      role: apiFnRole,
      timeout: cdk.Duration.seconds(10),
      environment: {
        BUCKET_NAME: filesBucket.bucketName,
        USER_POOL_ID: userPool.userPoolId,
        CLIENT_ID: userPoolClient.userPoolClientId,
      },
    })


    const httpApi = new apigwv2.HttpApi(this, 'VaultShareApi', {
      apiName: 'vaultshare-api',
    })
    httpApi.addRoutes({
      path: '/files',
      methods: [apigwv2.HttpMethod.GET],
      integration: new apigwv2int.HttpLambdaIntegration('FilesInt', apiFn),
    });

    httpApi.addRoutes({
      path: '/admin/files',
      methods: [apigwv2.HttpMethod.GET],
      integration: new apigwv2int.HttpLambdaIntegration('AdminInt', apiFn),
    });

    authenticatedRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
      resources: [
        `${filesBucket.bucketArn}/users/` +
          '${cognito-identity.amazonaws.com:sub}/*',
      ],
    }));

    authenticatedRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['s3:ListBucket'],
      resources: [filesBucket.bucketArn], //which target the statement applies to.
      conditions: {
        StringLike: {
          's3:prefix': ['users/${cognito-identity.amazonaws.com:sub}/*'],
        },
      },
    }));

    authenticatedRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
      resources: [filesKey.keyArn],
      conditions: {
        StringEquals: { 'kms:ViaService': `s3.${this.region}.amazonaws.com` },
      },
    }));

    new cognito.CfnUserPoolGroup(this, 'AdminsGroup', {
      userPoolId: userPool.userPoolId,
      groupName: 'admins',
      description: 'Full bucket access',
    })

    new cognito.CfnIdentityPoolRoleAttachment(this, 'IdentityPoolRoles', {
      identityPoolId: identityPool.ref,
      roles: {
        authenticated: authenticatedRole.roleArn,
      },
    });

    //Outputs
    new cdk.CfnOutput(this, 'BucketName', { value: filesBucket.bucketName})
    new cdk.CfnOutput(this, 'KeyArn', { value: filesKey.keyArn })
    new cdk.CfnOutput(this, 'FunctionName', {value: filesFn.functionName });
    new cdk.CfnOutput(this, 'RoleArn', {value: filesFnRole.roleArn})  
    new cdk.CfnOutput(this, 'ReportsRoleArn', { value: reportsRole.roleArn });
    new cdk.CfnOutput(this, 'UserPoolId', { value: userPool.userPoolId });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: userPoolClient.userPoolClientId });
    new cdk.CfnOutput(this, 'IdentityPoolId', { value: identityPool.ref });  
    new cdk.CfnOutput(this, 'ApiUrl', { value: httpApi.apiEndpoint });
  }
}
