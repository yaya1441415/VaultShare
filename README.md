# VaultShare

A secure multi-tenant file store built to learn AWS identity properly: IAM policy
evaluation, envelope encryption, temporary credentials, and federated identity.

Every concept here was deployed, then verified against the running account with the
CLI — not just written and assumed to work. Where an experiment contradicted what I
expected, the contradiction is documented rather than smoothed over.

Built with AWS CDK (TypeScript).

---

## Architecture

```
Browser ──email+password──> Cognito User Pool          (authentication)
        <──ID/access/refresh JWTs──

Browser ──ID token──────────> Cognito Identity Pool     (authorization)
                                      │
                                      │ sts:AssumeRoleWithWebIdentity
                                      ▼
                                     STS
        <──AccessKeyId/SecretKey/SessionToken (1 hour)──

Browser ──signed request────> S3 directly               (no backend in the byte path)
                               │
                               │ kms:GenerateDataKey / kms:Decrypt (as the caller)
                               ▼
                              KMS CMK

Browser ──Bearer access token─> API Gateway ──> Lambda  (metadata operations)
                                                  │ verifies JWT in code
                                                  ▼
                                                 S3 (ListBucket)
```

Two access paths, deliberately. The direct path has IAM enforcing per-user isolation.
The API path has application code enforcing it. The difference between them is the most
interesting thing in this repo — see [Two authorization models](#two-authorization-models).

---

## Concept map

| Concept | Where it lives |
|---|---|
| Resource-based policy | `lib/vaultshare-stack.ts` — bucket policy, KMS key policy, role trust policies |
| Identity-based policy | `lib/vaultshare-stack.ts` — `addToPolicy` calls on each role |
| AWS-managed vs customer-managed | `AWSLambdaBasicExecutionRole` vs. hand-written S3/KMS statements |
| Bucket-level vs object-level ARNs | `s3:ListBucket` on `bucketArn`, `s3:GetObject` on `arnForObjects('*')` |
| Explicit deny as a guardrail | `enforceSSL: true` → deny all S3 over plain HTTP |
| Envelope encryption | `encryption: KMS` + `encryptionKey` + `bucketKeyEnabled` |
| KMS policy evaluation | key policy grant, IAM grant, and `kms:ViaService` scoping |
| Trust policy vs permission policy | `VaultShareReportsReader` — `assumedBy` vs `addToPolicy` |
| `sts:AssumeRole` | `VaultShareReportsReader`, assumed manually from the CLI |
| `sts:AssumeRoleWithWebIdentity` | `VaultShareAuthenticatedUser`, assumed via the Identity Pool |
| Per-user isolation via policy variable | `users/${cognito-identity.amazonaws.com:sub}/*` |
| Federated principal + `aud` pinning | `CognitoAuthenticatedRole` trust policy |
| JWT verification (5 checks) | `lambda/api/index.ts` — `aws-jwt-verify` |
| Group-based authorization | `cognito:groups` read from a verified token |
| OAuth authorization code flow | Cognito hosted domain + `authorizationCodeGrant` |

---

## Resources deployed

| Resource | Purpose |
|---|---|
| KMS CMK (`alias/vaultshare-files`) | Customer-managed key with a policy I control |
| S3 bucket | SSE-KMS, versioned, HTTPS-only, TLS 1.2 minimum, public access blocked |
| `FilesFnRole` + `FilesFn` | Reads/writes objects; used to test KMS evaluation |
| `VaultShareReportsReader` | Assumable role scoped to `reports/*`; STS demo |
| Cognito User Pool + app client | User directory, issues JWTs |
| Cognito Identity Pool | Brokers JWTs for AWS credentials |
| `VaultShareAuthenticatedUser` | Role every authenticated user assumes |
| `ApiFnRole` + `ApiFn` | HTTP API backend; verifies JWTs in code |
| HTTP API (`/files`, `/admin/files`) | Metadata operations |
| Cognito hosted domain | Serves the login page and receives OAuth redirects |

---

## Two authorization models

The same isolation requirement, solved two ways.

### Direct to S3 — IAM enforces it

```
arn:aws:s3:::<bucket>/users/${cognito-identity.amazonaws.com:sub}/*
```

That `${...}` is an IAM policy variable, resolved at request time from the caller's
STS session. Every authenticated user assumes the same role, and every user is
confined to their own prefix.

The client controls the path in the request. It cannot control the path the policy
builds from its identity. Access is granted only where the two agree.

One statement. Unlimited users. No application code.

`s3:ListBucket` needs separate treatment, because it operates on the *bucket* ARN
rather than the object ARN and so can't be scoped by path. It's scoped with an
`s3:prefix` condition instead — without that, any user could enumerate every other
user's folder names.

### Through the API — application code enforces it

```typescript
Prefix: `users/${sub}/`
```

`ApiFnRole` is genuinely permitted to list the entire bucket. The only thing
restricting results to one user is that `Prefix` argument. Delete it and every user
sees every file, and IAM raises no objection, because nothing was violated.

**The direct path fails safe; the API path fails open.** That asymmetry is the
argument for pushing authorization into IAM wherever the shape of the problem allows
it.

---

## Verified behaviour

Each of these was run against the deployed stack.

### Policy types are distinguishable in the deployed artifacts

```
aws iam get-role-policy  --role-name <role> --policy-name <policy>   → no Principal
aws kms get-key-policy   --key-id <key-id>  --policy-name default    → every statement has a Principal
```

Identity policies name resources and omit principals. Resource policies name
principals and omit resources — a key policy's `Resource: "*"` means "this key."

### KMS evaluation is not what I first believed

I was told KMS requires the permission in *both* the key policy and an IAM policy.
I removed the role's KMS statement expecting a denial and the call succeeded.

The AWS documentation is precise:

> No AWS principal has any permissions to a KMS key unless they are explicitly
> allowed... in a key policy, IAM policy, **or grant**.

*Or.* Results:

| Key policy | IAM policy | Outcome |
|---|---|---|
| Names the role directly | nothing | works |
| Root delegation only | grants `kms:Decrypt` | works |
| Root delegation only | nothing | denied |

The key policy is always the gatekeeper — an IAM policy alone can never reach a key.
But a key policy statement naming the principal is a complete grant on its own. The
"both" requirement applies only to the IAM route, which depends on the root-delegation
statement (`Principal: <account>:root`, `Action: kms:*`) being present. Remove that
statement and IAM policies are inert against the key regardless of how permissive
they are — and the key is unrecoverable.

### Services forward the caller's identity

S3 calls KMS as the *caller*, not as itself. So a role needs `kms:GenerateDataKey`
for uploads and `kms:Decrypt` for downloads even though its code never calls KMS.

Consequence: an `AccessDenied` on `PutObject` can be a KMS problem. The operation
named in the error is the S3 one.

This is also why the identity-side KMS grant is kept even though the key policy grant
makes it redundant — the IAM statement is what carries the `kms:ViaService` condition,
restricting the key to requests arriving through S3. Stolen credentials can't decrypt
arbitrary ciphertext.

### Assuming a role replaces your identity

```
as yahya-dev (admin):            reports/q1.txt ✓    test.txt ✓
as VaultShareReportsReader:      reports/q1.txt ✓    test.txt ✗ 403
```

Permissions don't stack. The role's policy is consulted instead of the user's, not in
addition to it. The failure is the proof the swap took effect.

Sessions expire on their own — one died mid-session with `ExpiredToken`. Nothing had
to be revoked or cleaned up.

### Per-user isolation holds

```
upload users/<my-identity-id>/mine.txt        → OK
upload users/someone-else/stolen.txt          → AccessDenied
download <bucket-root>/test.txt               → 403
```

The denial message is worth reading: *"because no identity-based policy allows the
s3:PutObject action."* Not an explicit deny — no statement matched, and the default
is deny.

### Token verification catches the classic bug

| Request | Result |
|---|---|
| No `Authorization` header | 401 |
| Valid access token | 200 |
| Valid **ID** token | 401 |
| Valid access token, `/admin/files`, not in `admins` | 403 |

The ID token is correctly signed, unexpired, from the right pool and the right client.
It's rejected because `token_use` is `id` and the verifier is configured for `access`.
Sending the wrong token type is the most common Cognito mistake; one config line
catches it.

401 and 403 mean different things: "I don't know who you are" versus "I know exactly
who you are, and no."

---

## Security notes

### The `aud` condition is load-bearing

```json
"Principal": { "Federated": "cognito-identity.amazonaws.com" },
"Action": "sts:AssumeRoleWithWebIdentity",
"Condition": {
  "StringEquals": { "cognito-identity.amazonaws.com:aud": "<my-identity-pool-id>" },
  "ForAnyValue:StringLike": { "cognito-identity.amazonaws.com:amr": "authenticated" }
}
```

The principal is a *shared AWS service*, not my pool. Without the `aud` condition, any
Cognito Identity Pool in any AWS account can assume this role — someone creates a pool
in their own account, authenticates, and walks in.

`amr` restricts it to authenticated identities, excluding guests.

There is no L2 CDK construct for Identity Pools, so this trust policy is written by
hand. That's worth knowing: the convenience layer that would normally stop you
omitting a critical condition isn't there.

### Group membership comes only from verified claims

```typescript
const groups = (claims['cognito:groups'] as string[]) ?? [];
const isAdmin = groups.includes('admins');
```

`claims` exists only because `verifier.verify()` passed. Reading admin status from a
header or query parameter would be trivially forgeable; reading it from a signed token
is not, because modifying the payload invalidates the signature.

Changing a user's groups does not change tokens already issued. Stale claims stay valid
until expiry — the trade-off for stateless verification.

### `grant*` methods vs hand-written policies

`filesKey.grantEncryptDecrypt(fn)` generates `kms:Encrypt`, `kms:ReEncrypt*`,
`kms:GenerateDataKey*`, `kms:Decrypt` and `kms:DescribeKey`. The narrow hand-written
version grants `kms:GenerateDataKey` and `kms:Decrypt` only, which is what this
workload needs.

CDK's grant methods are correct and well-tested, and slightly more permissive than the
minimum. This repo uses the narrow version and keeps the broader one in git history for
comparison.

### Known gaps in this deployment

Things a production deployment would do differently, listed because knowing the gap
matters more than hiding it:

- **`yahya-dev` is an admin IAM user with permanent access keys.** Admin rights plus a
  long-lived secret on a laptop is exactly what STS exists to avoid. The production
  pattern is a user with almost nothing except `sts:AssumeRole`, an `AdminRole`
  requiring MFA in its trust policy, and daily work in narrow roles.
- **`USER_PASSWORD_AUTH` is enabled** on the app client, which sends the password to
  Cognito. Necessary for CLI testing; a real frontend uses SRP, where the password never
  leaves the device. Production would disable the password flow entirely.
- **No MFA** on the User Pool.
- **`bucketKeyEnabled: true`** trades CloudTrail granularity for cost. It cuts KMS
  calls substantially, but you no longer get one KMS event per object, so per-object
  decrypt auditing gets coarse. A compliance regime requiring "prove which objects this
  role decrypted" would want it off.

---

## Known design consideration: two subject identifiers

Cognito issues two different IDs for the same person.

| ID | Issued by | Where it appears |
|---|---|---|
| `8cadb588-...` | User Pool | the `sub` claim in ID and access tokens |
| `ca-central-1:b9d2058b-...` | Identity Pool | the STS session, and `${cognito-identity.amazonaws.com:sub}` |

The direct-to-S3 path enforces isolation on the **identity pool** sub, so objects live
at `users/ca-central-1:b9d2058b-.../`.

The API only receives a User Pool access token, which carries the **user pool** sub. So
`GET /files` filters on `users/8cadb588-.../`, matches nothing, and returns an empty
list.

```
$ curl -H "Authorization: Bearer <token>" $API/files
{"sub":"8cadb588-5091-70f0-5091-31a35b31cdd3","groups":[],"keys":[]}

$ aws s3 ls s3://<bucket>/users/ --recursive
2026-09-20 17:24:28   15   users/ca-central-1:b9d2058b-.../mine.txt
```

No error. A 200 with an empty array. The token verified, the code ran, S3 answered —
about the wrong prefix.

The clue is in the variable name: `cognito-identity` is the Identity Pool;
`cognito-idp` is the User Pool. Two service prefixes, easily missed.

Left unresolved deliberately. Three fixes, none free:

- **Pass the ID token to the API** and resolve the identity ID via
  `cognito-identity:GetId`. Extra round trip, extra coupling.
- **Key storage on the user pool sub.** Not possible without losing IAM-enforced
  isolation — STS exposes only the identity pool sub as a policy variable.
- **Persist the mapping** on first sign-in and look it up. The production answer.

The wider point: mixing IAM-enforced and application-enforced authorization means two
identity models have to agree, and nothing warns you when they don't.

---

## Notes on CDK

CDK is not an AWS service. It's a program that prints a CloudFormation template.
`enforceSSL: true` isn't a bucket setting — there is no such flag in S3. It makes CDK
emit an `AWS::S3::BucketPolicy` with `Effect: Deny`, `Principal: "*"`, `Action: s3:*`,
two resource ARNs, and an `aws:SecureTransport` condition. The policy exists either
way; the prop just means you didn't type it.

So the habit that matters isn't writing policies by hand. It's running `cdk synth` and
reading what you generated. Several of the findings above came from doing that.

Two things worth knowing:

- **Source order isn't deployment order.** CDK builds a dependency graph from
  references between constructs; CloudFormation creates resources in whatever order
  satisfies it. `encryptionKey: filesKey` records an edge and emits an `Fn::GetAtt`
  token, not an ARN. `console.log(key.keyArn)` prints `${Token[TOKEN.42]}` — you can't
  do string manipulation on CDK-generated ARNs.
- **Policy variables must survive TypeScript.** `${cognito-identity.amazonaws.com:sub}`
  has to reach AWS literally, so it lives in a single-quoted string concatenated onto a
  template literal. Inside backticks, TypeScript would try to interpolate it.

---

## Running it

```bash
npm install
cdk bootstrap        # first time in this account/region only
cdk diff             # read this before every deploy
cdk deploy
```

`cdk diff` caught two problems before anything reached AWS: an em dash in an IAM
description (only ASCII and Latin-1 are accepted) and a deprecated Lambda runtime.
That's the argument for running it habitually rather than going straight to `deploy`.

Stack outputs give you the bucket name, key ARN, pool IDs, API URL, and hosted UI
domain:

```bash
aws cloudformation describe-stacks --stack-name VaultShareStack \
  --query "Stacks[0].Outputs" --output table
```

Set a billing alarm before deploying. The CMK is roughly $1/month; everything else sits
in the free tier at this scale. `cdk destroy` tears it down — `removalPolicy: DESTROY`
is set throughout because this is a learning environment, and the default for KMS is
`RETAIN`.

---

## Status

| Topic | Status |
|---|---|
| IAM architecture and policy types | complete |
| Identity tokens and temporary credentials | complete |
| User Pools vs. Identity Pools | complete |
| Own API with JWT verification | complete |
| OIDC federation | hosted domain and authorization code flow deployed; Google provider not yet wired up |
| SAML federation | not started |

Remaining work: add Google as an OIDC provider on the User Pool, add a SAML provider
(Okta or Entra ID), and build a minimal frontend so the flow is clickable rather than
CLI-driven.
