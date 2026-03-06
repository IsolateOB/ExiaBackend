use crate::models::Claims;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use worker::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
}

fn sign_input(input: &str, secret: &str) -> Result<Vec<u8>, String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "failed to initialize hmac".to_string())?;
    mac.update(input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn encode_jwt_hs256<T: Serialize>(claims: &T, secret: &str) -> Result<String, String> {
    let header = JwtHeader {
        alg: "HS256",
        typ: "JWT",
    };
    let encoded_header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|_| "failed to serialize jwt header".to_string())?,
    );
    let encoded_claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(claims).map_err(|_| "failed to serialize jwt claims".to_string())?,
    );
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = URL_SAFE_NO_PAD.encode(sign_input(&signing_input, secret)?);
    Ok(format!("{signing_input}.{signature}"))
}

pub fn decode_jwt_hs256(token: &str, secret: &str, now: i64) -> Result<Claims, String> {
    let mut parts = token.split('.');
    let header = parts.next().ok_or_else(|| "invalid token format".to_string())?;
    let claims = parts.next().ok_or_else(|| "invalid token format".to_string())?;
    let signature = parts.next().ok_or_else(|| "invalid token format".to_string())?;
    if parts.next().is_some() {
        return Err("invalid token format".to_string());
    }

    let signing_input = format!("{header}.{claims}");
    let expected_signature = sign_input(&signing_input, secret)?;
    let actual_signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "invalid signature encoding".to_string())?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "failed to initialize hmac".to_string())?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&actual_signature)
        .map_err(|_| "invalid signature".to_string())?;

    if actual_signature != expected_signature {
        return Err("invalid signature".to_string());
    }

    let claims_json = URL_SAFE_NO_PAD
        .decode(claims)
        .map_err(|_| "invalid claims encoding".to_string())?;
    let decoded_claims: Claims =
        serde_json::from_slice(&claims_json).map_err(|_| "invalid claims payload".to_string())?;
    if decoded_claims.exp <= now {
        return Err("token expired".to_string());
    }
    Ok(decoded_claims)
}

pub fn encode_claims_token(claims: &Claims, secret: &str) -> worker::Result<String> {
    encode_jwt_hs256(claims, secret).map_err(|err| Error::RustError(err.into()))
}

pub fn decode_claims_token(token: &str, secret: &str, now: i64) -> worker::Result<Claims> {
    decode_jwt_hs256(token, secret, now).map_err(|err| Error::RustError(err.into()))
}

#[cfg(test)]
mod tests {
    use super::{decode_jwt_hs256, encode_jwt_hs256};
    use crate::models::Claims;

    fn sample_claims(exp: i64) -> Claims {
        Claims {
            sub: "tester".to_string(),
            uid: 42,
            iat: 1_700_000_000,
            exp,
            iss: "exia-backend".to_string(),
            restricted: false,
        }
    }

    #[test]
    fn roundtrip_hs256_token() {
        let secret = "secret";
        let token = encode_jwt_hs256(&sample_claims(4_000_000_000), secret).expect("encode");
        let claims = decode_jwt_hs256(&token, secret, 1_800_000_000).expect("decode");
        assert_eq!(claims.uid, 42);
        assert_eq!(claims.sub, "tester");
    }

    #[test]
    fn rejects_expired_token() {
        let secret = "secret";
        let token = encode_jwt_hs256(&sample_claims(10), secret).expect("encode");
        let error = decode_jwt_hs256(&token, secret, 11).expect_err("should reject");
        assert!(error.contains("expired"));
    }

    #[test]
    fn rejects_tampered_token() {
        let secret = "secret";
        let token = encode_jwt_hs256(&sample_claims(4_000_000_000), secret).expect("encode");
        let mut parts: Vec<String> = token.split('.').map(|part| part.to_string()).collect();
        let signature_len = parts[2].len();
        let replacement = if parts[2].ends_with('a') { 'b' } else { 'a' };
        parts[2].replace_range(signature_len - 1..signature_len, &replacement.to_string());
        let tampered = parts.join(".");
        let error = decode_jwt_hs256(&tampered, secret, 1_800_000_000).expect_err("should reject");
        assert!(error.contains("signature"));
    }
}
