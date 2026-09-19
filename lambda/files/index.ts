import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';

const s3 = new S3Client({});


export const handler = async (event: unknown) => {
    try{
        const res = await s3.send(new GetObjectCommand({
            Bucket: process.env.BUCKET_NAME!,
            Key: 'test.txt',
        }));
        return { statusCode: 200, body: await res.Body!.transformToString() };
    } catch(err: any){
        return { statusCode: 500, body: `${err.name}: ${err.message}`};
    }
}