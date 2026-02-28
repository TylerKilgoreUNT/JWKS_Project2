use chrono::Utc;
use jsonwebtoken::{encode as jwt_encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::LineEnding;
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::time::Duration;
use warp::Filter;

#[tokio::main]
async fn main() {
    // Generate RSA key pair
    let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    const KID: &str = "goodKID";

    // Convert private key to PEM format
    let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();

    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();

    let method_not_allowed = warp::any().map(|| {
        warp::reply::with_status(
            "Method Not Allowed",
            warp::http::StatusCode::METHOD_NOT_ALLOWED,
        )
    });

    let auth = warp::path("auth").and(
        warp::post()
            .and(warp::query::<HashMap<String, String>>()) // Extract query parameters
            .map(move |params: HashMap<String, String>| {
                let mut claims = BTreeMap::new();
                claims.insert("sub", "1234567890");
                claims.insert("name", "John Doe");
                claims.insert("iat", "1516239022");

                let mut header = Header::default();
                header.alg = Algorithm::RS256;

                let expiration = if params.get("expired").is_some() {
                    Utc::now() - Duration::from_secs(3600) // Set to an hour ago to make it expired
                } else {
                    Utc::now() + Duration::from_secs(3600) // Valid for an hour
                };
                header.kid = Some(KID.to_string());
                if params.get("expired").is_some() {
                    header.kid = Some("expiredKID".to_string());
                }
                let exp_string = expiration.timestamp().to_string();
                claims.insert("exp", &exp_string);

                let token = jwt_encode(&header, &claims, &encoding_key).unwrap();
                warp::reply::with_status(token, warp::http::StatusCode::OK)
            })
            .or(method_not_allowed),
    );

    let jwks = warp::path!(".well-known" / "jwks.json").and(
        warp::get()
            .map(move || {
                let n = base64_url::encode(&get_modulus(&public_key));
                let e = base64_url::encode(&get_exponent(&public_key));

                let jwk = json!({
                    "kty": "RSA",
                    "kid": KID,
                    "use": "sig",
                    "n": n,
                    "e": e,
                    "alg": "RS256"
                });

                let jwks = json!({
                    "keys": [jwk]
                });

                warp::reply::json(&jwks)
            })
            .or(method_not_allowed),
    );

    let routes = auth.or(jwks);

    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}

fn get_modulus(public_key: &RsaPublicKey) -> Vec<u8> {
    public_key.n().to_bytes_be()
}

fn get_exponent(public_key: &RsaPublicKey) -> Vec<u8> {
    public_key.e().to_bytes_be()
}
