# axum-framework
นี่คือ README.md ฉบับสมบูรณ์ที่สรุปทุกขั้นตอนที่เราทำมา ตั้งแต่โครงสร้างโปรเจกต์ การตั้งค่า Google Cloud Console ไปจนถึงคำสั่งรัน เพื่อให้คุณ (หรือทีมงานในอนาคต) สามารถ Setup โปรเจกต์นี้ใหม่ได้ภายใน 5 นาทีครับ

คุณสามารถ Copy ข้อความด้านล่างนี้ไปสร้างไฟล์ README.md ไว้ที่ Root Project (axum-framework/README.md) ได้เลยครับ
# 🚀 axum-framework: High-Performance Trading System

A modular, high-performance backend framework built with **Rust**, **Axum 0.7**, and **Tokio**. Designed for scalability using a **Modular Monolith** architecture (Cargo Workspace).

## ✨ Features

* **Architecture:** Cargo Workspace (`api`, `auth`, `trade`, `common`) for clean separation of concerns.
* **Authentication:** Google OAuth2 implementation with secure session management via Cookies.
* **Performance:**
    * Zero-copy static file serving with `tower-http`.
    * Non-blocking async runtime (`tokio`).
* **Security:** Type-driven development, protected routes middleware, and secure error handling (No `unwrap()` in production logic).
* **Frontend:** Decoupled HTML/JS serving from `public/` directory.

---

## 🛠️ Project Structure

```text
axum-framework/
├── Cargo.toml              # Workspace Definition
├── .env                    # Environment Variables (Secrets)
├── public/                 # Static Assets (Frontend)
│   └── landing.html        # Dashboard Page
└── crates/
    └── api/                # Main Application Entry Point
        ├── Cargo.toml
        └── src/
            └── main.rs     # Server & Router Logic
⚙️ Setup Instructions
1. Prerequisites
Rust (Edition 2021)

VS Code (Recommended)

2. Google OAuth2 Configuration (Critical Step)
Before running the app, you must set up credentials in Google Cloud Console:

Go to Google Cloud Console.

Navigate to APIs & Services > Credentials.

Create a new OAuth 2.0 Client ID.

Important: Under Authorized redirect URIs, add exactly:

Plaintext

http://localhost:3000/auth/callback
Copy your Client ID and Client Secret.

3. Environment Variables
Create a file named .env at the project root (axum-framework/.env) and add your credentials:

# Google OAuth Credentials
GOOGLE_CLIENT_ID=your_client_id_from_google_console
GOOGLE_CLIENT_SECRET=your_client_secret_from_google_console
GOOGLE_REDIRECT_URL=http://localhost:3000/auth/callback

# Rust Configuration
RUST_LOG=api=debug,tower_http=debug
4. Dependencies
Ensure your crates/api/Cargo.toml has the correct dependencies enabled:

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tower-http = { version = "0.5", features = ["fs", "trace"] }
axum-extra = { version = "0.9", features = ["cookie", "typed-header"] }
oauth2 = "4.4"
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
dotenvy = "0.15"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }

🚀 Running the Project
cargo run -p api

Server URL: http://localhost:3000

Login Flow: Access the root URL -> Sign in with Google -> Redirect to Dashboard.
