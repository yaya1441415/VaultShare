import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { S3Client, ListObjectsV2Command } from '@aws-sdk/client-s3';

//S3 client -  empty braces means find credentials yourself.
const s3 = new S3Client({});

//reated once, outside the handler  teh verifier caches Cognito's
const verifier = CognitoJwtVerifier.create({
    userPoolId: process.env.USER_POOL_ID!,
    tokenUse: 'access',
    clientId: process.env.CLIENT_ID!,
})

export const handler = async (event: any) => {
    const auth = event.headers?.authorization ?? event.headers?.Authorization;
    if(!auth?.startsWith('Bearer ')) {
        return { statusCode: 401, body: JSON.stringify({ error: 'Missing bearer token' }) };
    }
    const token = auth.slice('Bearer '.length);

    let claims;
    try {
        // Checks signature, exp, iss, client_id, and token_use.
        // Throws on any failure.
        claims = await verifier.verify(token);
    } catch (err: any) {
        console.warn('rejected token:', err.message);
        return { statusCode: 401, body: JSON.stringify({ error: err.message }) };
    }    

    const sub = claims.sub
    const groups = (claims['cognito:groups'] as string[]) ?? [];
    const isAdmin = groups.includes('admins');
    const path = event.rawPath ?? '';

    if (path.startsWith('/admin/')) {
        if (!isAdmin) {
            return { statusCode: 403, body: JSON.stringify({ error: 'Not an admin' }) };
        }

        const res = await s3.send(new ListObjectsV2Command({
            Bucket: process.env.BUCKET_NAME!,
        })); 

        return {
            statusCode: 200,
            body: JSON.stringify({
                scope: 'all users',
                keys: res.Contents?.map(o => o.Key) ?? [],
            }),
        }
    }

    const res = await s3.send(new ListObjectsV2Command({
        Bucket: process.env.BUCKET_NAME!,
        Prefix: `users/${sub}/`,
    }));

    return {
        statusCode: 200,
        body: JSON.stringify({
        sub,
        groups,
        keys: res.Contents?.map(o => o.Key) ?? [],
        }),
    };
}