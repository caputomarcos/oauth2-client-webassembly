const { oauth2_flow } = require('./pkg/simple_wasm_oauth2');

const config = {
    client_id: "test_client_1",
    client_secret: "test_secret",
    auth_url: "http://localhost:8088/authorize",
    token_url: "http://localhost:8088/v1/oauth/tokens",
    device_auth_url: "http://localhost:8088/device"
};

async function getAccessToken(grantType, params) {
    try {
        const oauthParams = {
            grant_type: grantType,
            client_id: config.client_id,
            client_secret: config.client_secret,
            auth_url: config.auth_url,
            token_url: config.token_url,
            device_auth_url: config.device_auth_url,
            ...params
        };
        
        const tokenResponse = await oauth2_flow(oauthParams);
        console.log(`Access Token (${grantType}):`, tokenResponse);
    } catch (error) {
        console.error(`Error (${grantType}):`, error.message || error);
    }
}

// Example usage
getAccessToken('authorization_code', {
    proxy: {host: 'localhost', port: 3333, noproxy:['localhost']},
    code: 'your_auth_code', 
    redirect_uri: 'http://localhost:8088/redirect', 
    pkce_verifier: 'your_pkce_verifier' 
});
getAccessToken('password', { 
    username: 'test@user', 
    password: 'test_password' 
});
getAccessToken('client_credentials', {});
getAccessToken('refresh_token', { 
    refresh_token: 'b44b45c2-bc7e-4c8f-859b-6890d9d22eeb' 
});
getAccessToken('device_code', { 
    device_code: 'your_device_code' 
});
getAccessToken('implicity', { 
    code: 'your_device_code' 
});
