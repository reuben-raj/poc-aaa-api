import {
    CognitoIdentityProviderClient,
    InitiateAuthCommand,
    InitiateAuthResponse,
    AdminInitiateAuthCommand,
    AuthFlowType,
    InitiateAuthCommandOutput,
} from '@aws-sdk/client-cognito-identity-provider';
import * as crypto from 'crypto';

let cognitoClient: CognitoIdentityProviderClient;

export function initCognitoClient() {
    if (!cognitoClient) {
        cognitoClient = new CognitoIdentityProviderClient({
            region: process.env.REGION,
        });
    }
}

export function createAuthParams(
    username: string,
    password: string,
    clientId: string,
    clientSecret: string,
): InitiateAuthCommand {
    const secretHash = calculateSecretHash(username, clientId, clientSecret);
    let command = new InitiateAuthCommand({
        AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
        AuthParameters: {
            USERNAME: username,
            PASSWORD: password,
            SECRET_HASH: secretHash,
        },
        ClientId: clientId,
    });
    return command;
}

export async function initiateAuth(request: InitiateAuthCommand): Promise<InitiateAuthCommandOutput> {
    return cognitoClient.send(request);
}

export function createAdminAuthParams(
    username: string,
    password: string,
    clientId: string,
    clientSecret: string,
    userPoolId: string,
): AdminInitiateAuthCommand {
    const secretHash = calculateSecretHash(username, clientId, clientSecret);
    let command = new AdminInitiateAuthCommand({
        AuthFlow: AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
        AuthParameters: {
            USERNAME: username,
            PASSWORD: password,
            SECRET_HASH: secretHash,
        },
        ClientId: clientId,
        UserPoolId: userPoolId,
    });
    return command;
}

export async function initiateAdminAuth(request: AdminInitiateAuthCommand): Promise<InitiateAuthResponse> {
    return cognitoClient.send(request);
}

function calculateSecretHash(username: string, clientId: string, clientSecret: string): string {
    const hmac = crypto.createHmac('sha256', clientSecret);
    hmac.update(username + clientId);
    return hmac.digest('base64');
}
