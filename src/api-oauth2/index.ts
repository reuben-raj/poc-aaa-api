import {APIGatewayProxyEvent, APIGatewayProxyResult} from 'aws-lambda';
import {getLogger, initLogger} from 'opt/nodejs/util/logger';
import {createAuthParams, initCognitoClient, initiateAuth} from 'opt/nodejs/aws/aws';
import {InitiateAuthCommandOutput} from '@aws-sdk/client-cognito-identity-provider';
import {ApiError, ApiHeader, ApiParameter, ApiResponse} from 'opt/nodejs/util/constant';

interface ClientCredentials {
    clientId: string;
    clientSecret: string;
    grantType: string;
}

interface HeaderValue {
    authHeaderValue?: string;
    contentHeaderValue?: string;
}

initLogger('aaa-api-oauth2');

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const sanitizedEvent: APIGatewayProxyEvent = {...event};
    try {
        Object.freeze(sanitizedEvent);

        let clientCredentials = assessGrantType(sanitizedEvent);

        assessClientIdAndSecret(sanitizedEvent, clientCredentials);

        let clientId = clientCredentials?.clientId ?? process.env.APP_CLIENT_ID;
        let clientSecret = clientCredentials?.clientSecret ?? process.env.APP_CLIENT_SECRET;

        let globalHeaderValue = assessHeaders(sanitizedEvent, clientCredentials);

        let authResponse: InitiateAuthCommandOutput = await proceedToAuthenticate(
            globalHeaderValue,
            clientId,
            clientSecret,
        );

        return constructAuthenticationResponse(authResponse);
    } catch (error: any) {
        getLogger().error(sanitizedEvent.path, error);
        return handleError(error);
    }
};

function assessGrantType(sanitizedEvent: APIGatewayProxyEvent) {
    const paramGrantType = sanitizedEvent?.multiValueQueryStringParameters?.grant_type
        ? sanitizedEvent.multiValueQueryStringParameters.grant_type[0]
        : null;
    let body: string = sanitizedEvent?.body ? sanitizedEvent.body : '';
    let bodyGrantTypeRaw: string | undefined = body.split('&').find(x => x.indexOf(ApiParameter.GRANT_TYPE) != -1);
    if (paramGrantType && bodyGrantTypeRaw) {
        throw Error(ApiError.INVALID_REQUEST);
    } else if (bodyGrantTypeRaw) {
        if (bodyGrantTypeRaw.split('=')[1] === ApiParameter.CLIENT_CREDENTIALS) {
            return parseRequestBody(sanitizedEvent, 'body');
        } else {
            throw Error(ApiError.UNSUPPORTED_GRANT_TYPE);
        }
    } else if (paramGrantType) {
        if (paramGrantType === ApiParameter.CLIENT_CREDENTIALS) {
            return parseRequestBody(sanitizedEvent, 'param');
        } else {
            throw Error(ApiError.UNSUPPORTED_GRANT_TYPE);
        }
    } else {
        throw Error(ApiError.INVALID_REQUEST);
    }
}

function assessClientIdAndSecret(sanitizedEvent: APIGatewayProxyEvent, clientCredentials: ClientCredentials) {
    if (
        sanitizedEvent.multiValueQueryStringParameters?.client_id ||
        sanitizedEvent.multiValueQueryStringParameters?.client_secret
    ) {
        throw Error(ApiError.INVALID_REQUEST);
    }

    if (
        (clientCredentials?.clientId && !clientCredentials?.clientSecret) ||
        (!clientCredentials?.clientId && clientCredentials?.clientSecret)
    ) {
        throw Error(ApiError.INVALID_CLIENT);
    }
}

function assessHeaders(sanitizedEvent: APIGatewayProxyEvent, clientCredentials: ClientCredentials) {
    let headerValue = getHeaderValue(sanitizedEvent);

    if (
        headerValue.authHeaderValue?.split(' ')[0].toLowerCase() !==
            ApiHeader.AUTHORIZATION_VALUE_PREFIX.toLowerCase() ||
        (clientCredentials?.grantType === 'body' &&
            headerValue.contentHeaderValue?.toLowerCase() !== ApiHeader.CONTENT_TYPE_VALUE.toLowerCase())
    ) {
        throw Error(ApiError.INVALID_REQUEST);
    }

    return headerValue;
}

function getHeaderValue(sanitizedEvent: APIGatewayProxyEvent): HeaderValue {
    let authHeaderValue;
    let contentHeaderValue;
    for (const header in sanitizedEvent.headers) {
        if (header.toLowerCase() === ApiHeader.AUTHORIZATION.toLowerCase()) {
            authHeaderValue = sanitizedEvent.headers[header];
        }
        if (header.toLowerCase() === ApiHeader.CONTENT_TYPE.toLowerCase()) {
            contentHeaderValue = sanitizedEvent.headers[header];
        }
        if (authHeaderValue && contentHeaderValue) break;
    }

    return {authHeaderValue: authHeaderValue, contentHeaderValue: contentHeaderValue};
}

async function proceedToAuthenticate(globalHeaderValue: HeaderValue, clientId: string, clientSecret: string) {
    let username = GetUserName(sanitize(globalHeaderValue.authHeaderValue));
    let password = GetUserPassword(sanitize(globalHeaderValue.authHeaderValue));
    if (!username || !password) {
        throw Error(ApiError.INVALID_REQUEST);
    }

    initCognitoClient();
    let authParams = createAuthParams(username, password, clientId, clientSecret);
    return await initiateAuth(authParams);
}

function GetUserName(authHeader: string): string {
    const authDetails = Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf8');
    const userName = authDetails.split(':')[0];
    return userName;
}

function GetUserPassword(authHeader: string): string {
    const authDetails = Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf8');
    const password = authDetails.substring(authDetails.indexOf(':') + 1, authDetails.length);
    return password;
}

function parseRequestBody(event: APIGatewayProxyEvent, grantType: string): ClientCredentials {
    let body = sanitize(<string>event.body);

    let clientIdParam = body?.split('&amp;')?.find((x: string) => x.indexOf(ApiParameter.CLIENT_ID) != -1);
    let clientSecretParam = body?.split('&amp;')?.find((x: string) => x.indexOf(ApiParameter.CLIENT_SECRET) != -1);

    let clientId = clientIdParam?.split('=')[1];
    let clientSecret = clientSecretParam?.split('=')[1];

    return {clientId: clientId, clientSecret: clientSecret, grantType: grantType};
}

function constructAuthenticationResponse(authResponse: InitiateAuthCommandOutput) {
    if (!authResponse?.AuthenticationResult?.AccessToken || !authResponse?.AuthenticationResult?.ExpiresIn) {
        throw Error(ApiError.INVALID_GRANT);
    } else {
        let responseBody = {
            access_token: authResponse.AuthenticationResult.AccessToken,
            expires_in: authResponse.AuthenticationResult.ExpiresIn,
            token_type: ApiResponse.TOKEN_TYPE,
        };

        return {
            statusCode: 200,
            body: JSON.stringify(responseBody),
        };
    }
}

function handleError(error: any) {
    if (error.name === 'NotAuthorizedException' || error.message === ApiError.INVALID_GRANT) {
        if (error.message.indexOf('Incorrect username') != -1 || error.message.indexOf('does not match') != -1) {
            return buildErrorResponse(400, ApiError.INVALID_CLIENT);
        }

        return buildErrorResponse(400, ApiError.INVALID_GRANT);
    } else if (error.name === 'ResourceNotFoundException' || error.message === ApiError.INVALID_CLIENT) {
        return buildErrorResponse(400, ApiError.INVALID_CLIENT);
    } else if (error.message === ApiError.INVALID_REQUEST) {
        return buildErrorResponse(400, ApiError.INVALID_REQUEST);
    } else if (error.message === ApiError.UNSUPPORTED_GRANT_TYPE) {
        return buildErrorResponse(400, ApiError.UNSUPPORTED_GRANT_TYPE);
    } else {
        return buildErrorResponse(500, ApiError.SERVER_ERROR);
    }
}

function buildErrorResponse(statusCode: number, error: string): {statusCode: number; body: string} {
    return {
        statusCode: statusCode,
        body: JSON.stringify({error: error}),
    };
}

function sanitize(value?: string) {
    const he = require('he');
    if (!value) return undefined;
    return he.escape(value);
}
