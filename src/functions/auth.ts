import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import * as jwt from "jsonwebtoken";

export async function auth(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
    try {
        const query = request.query;
        const clientId = query.get('client_id');
        const clientSecret = query.get('client_secret');
        if (clientId && clientSecret) {
            const savedClientSecret = `${process.env[clientId]}`;
            const jwtSecretKey = `${process.env['jwt_secret_key']}`;
            const jwtExpiresIn = parseInt(`${process.env['jwt_expire_time']}`);
            if (savedClientSecret
                    && savedClientSecret === clientSecret
                    && jwtSecretKey
                    && jwtExpiresIn) {
                const token = jwt.sign({
                    client_id: clientId,
                    token_type: 'Bearer'
                }, jwtSecretKey, {
                    expiresIn: jwtExpiresIn
                });
                return {
                    status: 200,
                    headers: {
                        'content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        'access_token': token,
                        'token_type': 'Bearer',
                        'expiresIn': jwtExpiresIn - 10
                    })
                };
            }
        }
    } catch (error) {
        context.log(error);
    }
    return {
        status: 400,
        headers: {
            'content-Type': 'application/json'
        },
        body: JSON.stringify({
            error: 'Invalid credential'
        })
    };
};

app.http('auth', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: auth
});
