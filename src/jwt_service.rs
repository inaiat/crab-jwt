use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use napi::{Error, Result, Status};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[napi(object)]
pub struct Claims {
  pub aud: Vec<String>,
  pub iss: String,
  pub sub: String,
  pub email: Option<String>,
  pub exp: u32,
}

#[derive(Clone)]
#[napi]
pub struct JwtService {
  kid: String,
  encoding_key: EncodingKey,
}

#[napi]
impl JwtService {
  #[napi(constructor)]
  pub fn new(kid: String, private_key_pem: String) -> Self {
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();

    JwtService { kid, encoding_key }
  }

  #[napi]
  pub fn generate_token(&self, claim: Claims) -> Result<String> {
    let header = Header {
      alg: Algorithm::RS256,
      kid: Some(self.kid.to_owned()),
      ..Default::default()
    };

    match encode(&header, &claim, &self.encoding_key) {
      Ok(t) => Ok(t),
      Err(e) => Err(Error::new(Status::GenericFailure, e.to_string())),
    }
  }
}
