use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use oauth2::{
    AuthorizationCode, AuthUrl, ClientId, ClientSecret, PkceCodeVerifier, TokenUrl,
    basic::{BasicClient, BasicTokenType}, reqwest::async_http_client, ResourceOwnerPassword, ResourceOwnerUsername,
    RefreshToken, RedirectUrl, EmptyExtraTokenFields, StandardTokenResponse, StandardErrorResponse,
};
use js_sys::Promise;
use std::borrow::Cow;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};

#[derive(Debug, Deserialize)]
struct OAuth2Params {
    grant_type: String,
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    pkce_verifier: Option<String>,
    username: Option<String>,
    password: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Debug)]
enum OAuth2GrantType {
    AuthorizationCode {
        code: String,
        redirect_uri: String,
        pkce_verifier: Option<String>,
    },
    Implicit,
    ResourceOwnerPassword {
        username: String,
        password: String,
    },
    ClientCredentials,
    RefreshToken {
        refresh_token: String,
    },
}

impl OAuth2GrantType {
    fn from_params(params: &OAuth2Params) -> Result<OAuth2GrantType, JsValue> {
        match params.grant_type.as_str() {
            "authorization_code" => Ok(OAuth2GrantType::AuthorizationCode {
                code: params.code.clone().ok_or_else(|| JsValue::from_str("Authorization code is required"))?,
                redirect_uri: params.redirect_uri.clone().ok_or_else(|| JsValue::from_str("Redirect URI is required"))?,
                pkce_verifier: params.pkce_verifier.clone(),
            }),
            "implicit" => Ok(OAuth2GrantType::Implicit),
            "password" => Ok(OAuth2GrantType::ResourceOwnerPassword {
                username: params.username.clone().ok_or_else(|| JsValue::from_str("Username is required"))?,
                password: params.password.clone().ok_or_else(|| JsValue::from_str("Password is required"))?,
            }),
            "client_credentials" => Ok(OAuth2GrantType::ClientCredentials),
            "refresh_token" => Ok(OAuth2GrantType::RefreshToken {
                refresh_token: params.refresh_token.clone().ok_or_else(|| JsValue::from_str("Refresh token is required"))?,
            }),
            _ => Err(JsValue::from_str("Unsupported grant type")),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum OAuth2Response {
    Standard(StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>),
    Error {
        error: String,
        access_token_url: String,
        authorization_endpoint: String,
    },
}

#[wasm_bindgen]
pub fn oauth2_flow(params: JsValue) -> Promise {
    future_to_promise(async move {
        let params: OAuth2Params = from_value(params).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let client = create_client(&params)?;

        let grant = OAuth2GrantType::from_params(&params)?;
        let response = handle_grant(grant, client, &params).await;

        Ok(to_value(&response).map_err(|e| JsValue::from_str(&e.to_string()))?)
    })
}

fn create_client(params: &OAuth2Params) -> Result<BasicClient, JsValue> {
    Ok(BasicClient::new(
        ClientId::new(params.client_id.clone()),
        Some(ClientSecret::new(params.client_secret.clone())),
        AuthUrl::new(params.auth_url.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?,
        Some(TokenUrl::new(params.token_url.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?),
    ))
}

async fn handle_grant(grant: OAuth2GrantType, client: BasicClient, params: &OAuth2Params) -> OAuth2Response {
    match grant {
        OAuth2GrantType::AuthorizationCode { code, redirect_uri, pkce_verifier } => {
            let mut req = client.exchange_code(AuthorizationCode::new(code));
            if let Some(verifier) = pkce_verifier {
                req = req.set_pkce_verifier(PkceCodeVerifier::new(verifier));
            }
            req = req.set_redirect_uri(Cow::Owned(RedirectUrl::new(redirect_uri).unwrap()));
            match req.request_async(async_http_client).await {
                Ok(token) => OAuth2Response::Standard(token),
                Err(e) => handle_error(e, params).await,
            }
        }
        OAuth2GrantType::Implicit => {
            OAuth2Response::Error {
                error: "Implicit grant type is not supported".to_string(),
                access_token_url: params.token_url.clone(),
                authorization_endpoint: params.auth_url.clone(),
            }
        }
        OAuth2GrantType::ResourceOwnerPassword { username, password } => {
            match client.exchange_password(
                &ResourceOwnerUsername::new(username),
                &ResourceOwnerPassword::new(password),
            ).request_async(async_http_client).await {
                Ok(token) => OAuth2Response::Standard(token),
                Err(e) => handle_error(e, params).await,
            }
        }
        OAuth2GrantType::ClientCredentials => {
            match client.exchange_client_credentials()
                .request_async(async_http_client).await {
                Ok(token) => OAuth2Response::Standard(token),
                Err(e) => handle_error(e, params).await,
            }
        }
        OAuth2GrantType::RefreshToken { refresh_token } => {
            match client.exchange_refresh_token(&RefreshToken::new(refresh_token))
                .request_async(async_http_client).await {
                Ok(token) => OAuth2Response::Standard(token),
                Err(e) => handle_error(e, params).await,
            }
        }
    }
}

async fn handle_error(err: oauth2::RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>, params: &OAuth2Params) -> OAuth2Response {
    let error_description = match err {
        oauth2::RequestTokenError::ServerResponse(response) => response.error().to_string(),
        oauth2::RequestTokenError::Request(reqwest_error) => format!("Request error: {}", reqwest_error),
        _ => format!("Unknown error: {:?}", err),
    };

    OAuth2Response::Error {
        error: error_description,
        access_token_url: params.token_url.clone(),
        authorization_endpoint: params.auth_url.clone(),
    }
}
