export class ApiError {
    static readonly INVALID_REQUEST = 'invalid_request';
    static readonly INVALID_CLIENT = 'invalid_client';
    static readonly INVALID_GRANT = 'invalid_grant';
    static readonly UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';
    static readonly UNAUTHORIZED_CLIENT = 'unauthorized_client';
    static readonly SERVER_ERROR = 'server_error';
}

export class ApiParameter {
    static readonly CLIENT_CREDENTIALS = 'client_credentials';
    static readonly GRANT_TYPE = 'grant_type';
    static readonly CLIENT_ID = 'client_id';
    static readonly CLIENT_SECRET = 'client_secret';
}

export class ApiHeader {
    static readonly AUTHORIZATION = 'Authorization';
    static readonly AUTHORIZATION_VALUE_PREFIX = 'basic';
    static readonly CONTENT_TYPE = 'Content-Type';
    static readonly CONTENT_TYPE_VALUE = 'application/x-www-form-urlencoded';
}

export class ApiResponse {
    static readonly TOKEN_TYPE = 'Bearer';
}
