import { fromByteArray as base64FromByteArray } from "base64-js";
import * as queryString from "query-string";
import { v4 as uuid } from "uuid";

interface IOAuth2RequestParams {
    client_id: string,
    redirect_uri: string,
    response_type: string,
    scope?: string
}

interface IProviderConfig {
    name: string,
    authorization_uri: string,
    client_id: string,
    customizeParams?: (authParams: IOAuth2RequestParams) => any
    scope?: string
};

interface IAuthorizationData {
    provider: string,
    token: string,
    expiresAt?: number
}

class Authorization {
    private readonly auth: IAuthorizationData;

    constructor(auth: IAuthorizationData) {
        this.auth = auth;
    }

    public provider() {
        return this.auth.provider;
    }

    public token() {
        return this.auth.token;
    }

    public expired() {
        if (this.auth.expiresAt) {
            return Date.now() - this.auth.expiresAt - 10000 < 0;
        } else {
            return false;
        }
    }
}

type AuthorizationBeginCallback = () => void | Promise<void>;
type AuthorizationCompleteCallback = (authorization: Authorization) => void;

interface IStorage<T> {
    save(value: any): void;
    load(): T | null;
    clear(): void;
}

type AuthStorage = IStorage<{ [provider: string]: IAuthorizationData }>;

type ReturnUriGenerator = (provider: string) => string;
type ReturnUri = string;

interface IOAuth2Options {
    authStorage: AuthStorage,
    stateStorage: IStorage<string>,
    returnUri: ReturnUri | ReturnUriGenerator
};

interface IOauth2SuccessResponse {
    access_token: string,
    token_type: string,
    expires_in?: string,
    scope?: string,
    state?: string
}

interface IOauth2ErrorResponse {
    error:
    "invalid_request"
    | "unauthorized_client"
    | "access_denied"
    | "unsupported_response_type"
    | "invalid_scope"
    | "server_error"
    | "temporarily_unavailable",
    error_description?: string,
    error_uri?: string,
    state: string
}

const isSuccessResponse = (response: any): response is IOauth2SuccessResponse => {
    return !!response.access_token;
}

class Oauth2AuthorizationError extends Error {
    public readonly provider: string;
    public readonly errorDescription?: string;
    public readonly errorUri?: string;

    constructor(provider: string, message: string, errorDescription?: string, errorUri?: string) {
        super(message);
        this.provider = provider;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;
    }
}

const generateState = (providerName: string) => ({
    id: uuid(),
    provider: providerName
});

const hash = async (text: string) => {
    const encoder = new TextEncoder();

    const hashBytes = await crypto.subtle.digest("sha-256", encoder.encode(text));
    return base64FromByteArray(new Uint8Array(hashBytes));
};

export default class Oauth2Client {
    private readonly returnUri: ReturnUri | ReturnUriGenerator;
    private readonly authStorage: AuthStorage;
    private readonly stateStorage: IStorage<string>;
    private readonly providers = new Map<string, IProviderConfig>();
    private readonly authBeginCallbacks: AuthorizationBeginCallback[] = [];
    private readonly authCompleteCallbacks: AuthorizationCompleteCallback[] = [];

    constructor(options: IOAuth2Options) {
        this.returnUri = options.returnUri;
        this.authStorage = options.authStorage;
        this.stateStorage = options.stateStorage;
    }

    public addProvider(providerConfig: IProviderConfig) {
        const providerName = providerConfig.name;

        this.providers.set(providerName, providerConfig);
    }

    public getAuthorization(provider: string) {
        const authorizations = this.authStorage.load();
        if (authorizations && authorizations[provider]) {
            return new Authorization(authorizations[provider]);
        } else {
            return null;
        }
    }

    public onAuthorizationBegin(cb: AuthorizationBeginCallback) {
        this.authBeginCallbacks.push(cb);
    }

    public onAuthorizationComplete(cb: AuthorizationCompleteCallback) {
        this.authCompleteCallbacks.push(cb);
    }

    public async authorize(providerName: string) {
        const providerConfig = this.providers.get(providerName);

        if (!providerConfig) {
            throw new Error("Not a known provider: " + providerName);
        }

        const returnUri = typeof this.returnUri === "function" ? this.returnUri(providerName) : this.returnUri;

        await Promise.all(this.authBeginCallbacks.map(cb => cb()));

        const state = JSON.stringify(generateState(providerName));
        this.stateStorage.save(state);

        let authParams: any = {
            client_id: providerConfig.client_id,
            redirect_uri: returnUri,
            response_type: "token",
            scope: providerConfig.scope || undefined
        };

        if (providerConfig.customizeParams) {
            authParams = providerConfig.customizeParams(authParams);
        }

        authParams.state = await hash(state);

        const authUri = `${providerConfig.authorization_uri}?${queryString.stringify(authParams)}`;

        location.href = authUri;
    }

    public async finishAuthorization() {
        const response: IOauth2SuccessResponse | IOauth2ErrorResponse = queryString.parse(location.hash);

        if (!response.state) {
            // There is no authorization to finish
            return;
        }

        const savedState = this.stateStorage.load();

        if (!savedState) {
            throw new Error("No saved state!");
        }

        this.stateStorage.clear();

        const stateHash = await hash(savedState);

        if (stateHash !== response.state) {
            throw new Error("state from response does not match saved state.")
        }

        const parsedState = JSON.parse(savedState);
        const provider = parsedState.provider;

        if (isSuccessResponse(response)) {
            const accessToken = response.access_token;
            const expiresIn = response.expires_in;

            const authData: IAuthorizationData = {
                expiresAt: expiresIn ? Date.now() + (parseInt(expiresIn, 10) * 1000) : undefined,
                provider,
                token: accessToken
            };

            const auths = this.authStorage.load() || {};
            auths[provider] = authData;
            this.authStorage.save(auths);

            const auth = new Authorization(authData);

            this.authCompleteCallbacks.forEach(cb => cb(auth));
        } else {
            // raise an error
            throw new Oauth2AuthorizationError(provider, response.error, response.error_description, response.error_uri);
        }
    }

    public async refresh(provider: string) {
        // TODO
        throw new Error("Not implemented.");
    }
}
