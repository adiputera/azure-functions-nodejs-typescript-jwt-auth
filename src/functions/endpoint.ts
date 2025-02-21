import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import * as jwt from "jsonwebtoken";

export async function endpoint(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
    try {
        const bearerToken = request.headers.get('Authorization');
        if (bearerToken && bearerToken.startsWith('Bearer ')) {
            const token = bearerToken.split(' ')[1];
            if (token) {
                const decoded = jwt.verify(token, `${process.env['jwt_secret_key']}`);
                if (decoded.client_id && `${process.env[decoded.client_id]}`) {
                    return {
                        status: 200,
                        headers: {
                            'content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            message: 'You have access to this endpoint'
                        })
                    };
                }
            }
        }
    } catch (error) {
        context.log(error);
    }
    return {
        status: 401,
        headers: {
            'content-Type': 'application/json'
        },
        body: JSON.stringify({
            error: 'Unauthorized'
        })
    };
};

app.http('endpoint', {
    methods: ['GET', 'POST'],
    authLevel: 'anonymous',
    handler: endpoint
});
