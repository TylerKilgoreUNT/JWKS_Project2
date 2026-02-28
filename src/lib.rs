use chrono::Utc;
use jsonwebtoken::{encode as jwt_encode, Algorithm, EncodingKey, Header};
use rand::thread_rng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use warp::{http::StatusCode, Filter, Rejection, Reply};

pub const DB_FILE: &str = "totally_not_my_privateKeys.db";

const TABLE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS keys(\
    kid INTEGER PRIMARY KEY AUTOINCREMENT,\
    key BLOB NOT NULL,\
    exp INTEGER NOT NULL\
)";

#[derive(Clone)]
pub struct AppState {
    db_path: Arc<String>,
}

impl AppState {
    pub fn new(db_path: impl Into<String>) -> Self {
        Self {
            db_path: Arc::new(db_path.into()),
        }
    }

    pub fn db_path(&self) -> &str {
        self.db_path.as_str()
    }
}

#[derive(Debug)]
struct StoredKey {
    kid: i64,
    key_pem: Vec<u8>,
}

#[derive(Serialize)]
struct JwtClaims {
    sub: &'static str,
    name: &'static str,
    iat: i64,
    exp: i64,
}

pub fn initialize_database(db_path: &str) -> Result<(), String> {
    let conn = Connection::open(db_path).map_err(|err| err.to_string())?;

    conn.execute(TABLE_SCHEMA, [])
        .map_err(|err| err.to_string())?;

    ensure_seed_keys(&conn)?;
    Ok(())
}

fn ensure_seed_keys(conn: &Connection) -> Result<(), String> {
    let now = Utc::now().timestamp();

    let expired_count: i64 = conn
        .query_row("SELECT COUNT(1) FROM keys WHERE exp <= ?1", [now], |row| {
            row.get(0)
        })
        .map_err(|err| err.to_string())?;

    if expired_count == 0 {
        let expired_pem = generate_private_key_pem()?;
        let expired_exp = now - 3600;
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?1, ?2)",
            params![expired_pem.into_bytes(), expired_exp],
        )
        .map_err(|err| err.to_string())?;
    }

    let valid_count: i64 = conn
        .query_row("SELECT COUNT(1) FROM keys WHERE exp > ?1", [now], |row| {
            row.get(0)
        })
        .map_err(|err| err.to_string())?;

    if valid_count == 0 {
        let valid_pem = generate_private_key_pem()?;
        let valid_exp = now + 3600;
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?1, ?2)",
            params![valid_pem.into_bytes(), valid_exp],
        )
        .map_err(|err| err.to_string())?;
    }

    Ok(())
}

fn generate_private_key_pem() -> Result<String, String> {
    let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).map_err(|err| err.to_string())?;
    private_key
        .to_pkcs1_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|err| err.to_string())
}

fn load_signing_key(db_path: &str, use_expired: bool) -> Result<StoredKey, String> {
    let conn = Connection::open(db_path).map_err(|err| err.to_string())?;
    let now = Utc::now().timestamp();

    let query = if use_expired {
        "SELECT kid, key FROM keys WHERE exp <= ?1 ORDER BY exp DESC LIMIT 1"
    } else {
        "SELECT kid, key FROM keys WHERE exp > ?1 ORDER BY exp ASC LIMIT 1"
    };

    conn.query_row(query, [now], |row| {
        Ok(StoredKey {
            kid: row.get(0)?,
            key_pem: row.get(1)?,
        })
    })
    .map_err(|err| err.to_string())
}

fn load_valid_private_keys(db_path: &str) -> Result<Vec<StoredKey>, String> {
    let conn = Connection::open(db_path).map_err(|err| err.to_string())?;
    let now = Utc::now().timestamp();

    let mut statement = conn
        .prepare("SELECT kid, key FROM keys WHERE exp > ?1 ORDER BY kid ASC")
        .map_err(|err| err.to_string())?;

    let rows = statement
        .query_map([now], |row| {
            Ok(StoredKey {
                kid: row.get(0)?,
                key_pem: row.get(1)?,
            })
        })
        .map_err(|err| err.to_string())?;

    let mut keys = Vec::new();
    for row in rows {
        keys.push(row.map_err(|err| err.to_string())?);
    }

    Ok(keys)
}

fn with_state(state: AppState) -> impl Filter<Extract = (AppState,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

pub fn build_routes(
    state: AppState,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    let method_not_allowed = warp::any()
        .map(|| warp::reply::with_status("Method Not Allowed", StatusCode::METHOD_NOT_ALLOWED));

    let auth = warp::path("auth").and(
        warp::post()
            .and(warp::query::<HashMap<String, String>>())
            .and(with_state(state.clone()))
            .map(auth_handler)
            .or(method_not_allowed.clone()),
    );

    let jwks = warp::path!(".well-known" / "jwks.json").and(
        warp::get()
            .and(with_state(state))
            .map(jwks_handler)
            .or(method_not_allowed),
    );

    auth.or(jwks)
}

fn auth_handler(params: HashMap<String, String>, state: AppState) -> impl Reply {
    let use_expired_key = params.contains_key("expired");
    let now = Utc::now().timestamp();

    let signing_key = match load_signing_key(state.db_path(), use_expired_key) {
        Ok(key) => key,
        Err(_) => {
            return warp::reply::with_status(
                "Failed to load signing key".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(signing_key.kid.to_string());

    let key_text = match String::from_utf8(signing_key.key_pem) {
        Ok(text) => text,
        Err(_) => {
            return warp::reply::with_status(
                "Stored signing key was not valid UTF-8".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let encoding_key = match EncodingKey::from_rsa_pem(key_text.as_bytes()) {
        Ok(key) => key,
        Err(_) => {
            return warp::reply::with_status(
                "Stored signing key was invalid".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let claims = JwtClaims {
        sub: "userABC",
        name: "userABC",
        iat: now,
        exp: if use_expired_key {
            now - 3600
        } else {
            now + 3600
        },
    };

    match jwt_encode(&header, &claims, &encoding_key) {
        Ok(token) => warp::reply::with_status(token, StatusCode::OK),
        Err(_) => warp::reply::with_status(
            "Failed to sign JWT".to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}

fn jwks_handler(state: AppState) -> impl Reply {
    let private_keys = match load_valid_private_keys(state.db_path()) {
        Ok(keys) => keys,
        Err(_) => {
            let body = json!({ "error": "Failed to load keys" });
            return warp::reply::with_status(
                warp::reply::json(&body),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let mut keys = Vec::new();

    for private_key in private_keys {
        let key_text = match String::from_utf8(private_key.key_pem) {
            Ok(text) => text,
            Err(_) => continue,
        };

        let parsed_private = match RsaPrivateKey::from_pkcs1_pem(&key_text) {
            Ok(key) => key,
            Err(_) => continue,
        };

        let public_key = RsaPublicKey::from(&parsed_private);
        let modulus = base64_url::encode(&public_key.n().to_bytes_be());
        let exponent = base64_url::encode(&public_key.e().to_bytes_be());

        keys.push(json!({
            "kty": "RSA",
            "kid": private_key.kid.to_string(),
            "use": "sig",
            "n": modulus,
            "e": exponent,
            "alg": "RS256"
        }));
    }

    let jwks = json!({ "keys": keys });
    warp::reply::with_status(warp::reply::json(&jwks), StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;
    use warp::test::request;

    fn setup_state() -> (AppState, TempDir) {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("test_private_keys.db");
        initialize_database(db_path.to_str().expect("invalid db path")).expect("failed to init db");
        (
            AppState::new(db_path.to_string_lossy().to_string()),
            temp_dir,
        )
    }

    fn load_key_ids(db_path: &str, expired: bool) -> Vec<i64> {
        let conn = Connection::open(db_path).expect("failed to open db");
        let now = Utc::now().timestamp();
        let query = if expired {
            "SELECT kid FROM keys WHERE exp <= ?1"
        } else {
            "SELECT kid FROM keys WHERE exp > ?1"
        };

        let mut statement = conn.prepare(query).expect("failed to prepare query");
        let rows = statement
            .query_map([now], |row| row.get::<_, i64>(0))
            .expect("failed to run query");

        rows.map(|row| row.expect("invalid row")).collect()
    }

    fn token_kid(token: &str) -> String {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let decoded = base64_url::decode(parts[0]).expect("invalid JWT header encoding");
        let json_value: serde_json::Value =
            serde_json::from_slice(&decoded).expect("invalid JWT header json");
        json_value["kid"].as_str().expect("missing kid").to_string()
    }

    #[test]
    fn database_stores_expired_and_valid_keys() {
        let (state, _temp_dir) = setup_state();
        let valid_keys = load_key_ids(state.db_path(), false);
        let expired_keys = load_key_ids(state.db_path(), true);

        assert!(!valid_keys.is_empty());
        assert!(!expired_keys.is_empty());
    }

    #[tokio::test]
    async fn post_auth_returns_valid_jwt() {
        let (state, _temp_dir) = setup_state();
        let routes = build_routes(state.clone());

        let response = request().method("POST").path("/auth").reply(&routes).await;

        assert_eq!(response.status(), StatusCode::OK);
        let token = std::str::from_utf8(response.body()).expect("response was not utf-8");
        let kid = token_kid(token);
        let valid_ids = load_key_ids(state.db_path(), false);
        assert!(valid_ids.contains(&kid.parse::<i64>().expect("kid was not numeric")));
    }

    #[tokio::test]
    async fn post_auth_expired_uses_expired_key() {
        let (state, _temp_dir) = setup_state();
        let routes = build_routes(state.clone());

        let response = request()
            .method("POST")
            .path("/auth?expired=1")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        let token = std::str::from_utf8(response.body()).expect("response was not utf-8");
        let kid = token_kid(token);
        let expired_ids = load_key_ids(state.db_path(), true);
        assert!(expired_ids.contains(&kid.parse::<i64>().expect("kid was not numeric")));
    }

    #[tokio::test]
    async fn get_jwks_returns_only_valid_keys() {
        let (state, _temp_dir) = setup_state();
        let routes = build_routes(state.clone());

        let response = request()
            .method("GET")
            .path("/.well-known/jwks.json")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let parsed: serde_json::Value =
            serde_json::from_slice(response.body()).expect("invalid json response");
        let keys = parsed["keys"].as_array().expect("keys was not an array");

        let valid_ids = load_key_ids(state.db_path(), false)
            .into_iter()
            .map(|kid| kid.to_string())
            .collect::<Vec<_>>();

        let expired_ids = load_key_ids(state.db_path(), true)
            .into_iter()
            .map(|kid| kid.to_string())
            .collect::<Vec<_>>();

        assert!(!keys.is_empty());

        for key in keys {
            let kid = key["kid"].as_str().expect("kid missing from jwks key");
            assert!(valid_ids.contains(&kid.to_string()));
            assert!(!expired_ids.contains(&kid.to_string()));
        }
    }

    #[tokio::test]
    async fn method_not_allowed_is_enforced() {
        let (state, _temp_dir) = setup_state();
        let routes = build_routes(state);

        let response = request().method("GET").path("/auth").reply(&routes).await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
