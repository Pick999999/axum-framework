use axum::{
    extract::{Query, State},
    http::{StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr, sync::Arc};
use tower_http::services::ServeFile; 
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// --- 1. App State ---
#[derive(Clone)]
struct AppState {
    oauth_client: BasicClient,
    http_client: ReqwestClient,
}

// --- 2. Main Entry Point ---
#[tokio::main]
async fn main() {
    // โหลด Environment Variables
    dotenvy::dotenv().ok();
    
    // Setup Logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "api=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // สร้าง App State
    let state = Arc::new(AppState {
        oauth_client: build_oauth_client(),
        http_client: ReqwestClient::new(),
    });

    // Router สำหรับส่วนที่ต้อง Login (Protected)
    let protected_routes = Router::new()
        .route_service("/landing", ServeFile::new("public/landing.html"))
        .route_layer(middleware::from_fn(auth_guard));

    // Router รวม
    let app = Router::new()
        .merge(protected_routes)
        .route("/", get(login_page_handler))
        .route("/auth/google", get(google_login_handler))
        .route("/auth/callback", get(google_callback_handler))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("🚀 Server started at http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.expect("Failed to bind port");
    axum::serve(listener, app).await.expect("Server failed");
}

// --- 3. Helpers ---
fn build_oauth_client() -> BasicClient {
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID in .env");
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET in .env");
    let redirect_url = env::var("GOOGLE_REDIRECT_URL").unwrap_or_else(|_| "http://localhost:3000/auth/callback".to_string());

    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
        .expect("Invalid token endpoint URL");

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).expect("Invalid redirect URL"))
}

// --- 4. Handlers ---

// หน้า Login
async fn login_page_handler() -> Html<&'static str> {
    Html(r#"
        <html>
            <body style="font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f0f2f5;">
                <div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center;">
                    <h1>axum-framework Login</h1>
                    <p>High Performance Trading Platform</p>
                    <a href="/auth/google" style="background-color: #4285F4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                        Sign in with Google
                    </a>
                </div>
            </body>
        </html>
    "#)
}

// Redirect ไป Google
async fn google_login_handler(State(state): State<Arc<AppState>>) -> Redirect {
    let (auth_url, _csrf_token) = state.oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.email".to_string()))
        .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.profile".to_string()))
        .url();
    Redirect::to(auth_url.as_str())
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    #[serde(rename = "state")]
    _state: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct GoogleUser {
    id: String,
    email: String,
    verified_email: bool,
    name: String,
    picture: String,
}

// Callback จาก Google
async fn google_callback_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<AuthRequest>,
) -> Result<(CookieJar, Redirect), AppError> {
    // 1. แลก Code เป็น Token
    let token = state.oauth_client
        .exchange_code(oauth2::AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| AppError::AuthError(format!("Token exchange failed: {}", e)))?;

    // 2. ดึงข้อมูล User (ตัวอย่าง: เพื่อเช็คว่า User มีจริง แต่ใน Demo นี้เรายังไม่ได้บันทึกลง DB)
    let _user_data: GoogleUser = state.http_client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|_| AppError::InternalError)?
        .json()
        .await
        .map_err(|_| AppError::InternalError)?;

    // 3. ฝัง Cookie
    let mut cookie = Cookie::new("auth-session", "valid-session-id");
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_same_site(SameSite::Lax);

    Ok((jar.add(cookie), Redirect::to("/landing")))
}

// --- 5. Middleware ---
async fn auth_guard(jar: CookieJar, req: axum::extract::Request, next: Next) -> Result<Response, AppError> {
    if let Some(_) = jar.get("auth-session") {
        Ok(next.run(req).await)
    } else {
        Ok(Redirect::to("/").into_response())
    }
}

// --- 6. Error Handling ---
enum AppError {
    AuthError(String),
    InternalError,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::AuthError(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error".to_string()),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}