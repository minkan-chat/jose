use serde_json::Value;

use super::AesKw;

/// Key Agreement with *E*lliptic Curve *D*iffie-*H*ellman *E*phemeral *S*tatic
/// (ECDH-ES) as defined in [section 4.6 of RFC 7518]
///
/// [section 4.6 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcDhES {
    /// The `epk` (Ephemeral Public Key) Header Parameter as defined in [section
    /// 4.6.1.1]
    ///
    /// [section 4.6.1.1]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.1>
    pub epk: Value,
    /// The "apu" (Agreement PartyUInfo) Header Parameter as defined in [section
    /// 4.6.1.2]
    ///
    /// [section 4.6.1.2]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2>
    pub apu: Value,
    /// The "apv" (Agreement PartyVInfo) Header Parameter as defined in [section
    /// 4.6.1.3]
    ///
    /// [section 4.6.1.3]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3>
    pub apv: Value,
    /// The mode of ECDH-ES will be used
    pub mode: EcDhESMode,
}

/// Different modes ECDH-ES can be used as defined in [section 4.6 of RFC 7518]
///
/// [section 4.6 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-4.6>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcDhESMode {
    /// Using ECDH-ES directly without any wrapping
    Direct,
    /// ECDH-ES using Concat KDF and CEK wrapped with one variant of [AesKw]
    AesKw(AesKw),
}
