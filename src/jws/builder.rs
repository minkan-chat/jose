use crate::{
    format::Format,
    header::{self, HeaderValue, JoseHeaderBuilder, JoseHeaderBuilderError},
    jwa::JsonWebSigningAlgorithm,
    JoseHeader, JsonWebSignature,
};

/// Builds a [`JsonWebSignature`] with custom header parameters.
#[derive(Debug)]
pub struct JsonWebSignatureBuilder<F: Format> {
    header: Result<F::JwsHeader, JoseHeaderBuilderError>,
}

impl<F: Format> JsonWebSignatureBuilder<F> {
    pub(super) fn new() -> Self {
        let default_header = JoseHeader::<F, header::Jws>::builder()
            .algorithm(HeaderValue::Protected(JsonWebSigningAlgorithm::None));

        let mut header = Err(JoseHeaderBuilderError::MissingAlgorithm);
        F::finalize_jws_header_builder(&mut header, default_header);

        Self { header }
    }

    /// Configures the custom header for this [`JsonWebSignature`].
    ///
    /// For [`Compact`](crate::format::Compact) and
    /// [`JsonFlattened`](crate::format::JsonFlattened) format, this method
    /// will set the single protected, and unprotected header if JSON flattened,
    /// header.
    ///
    /// ## Support for empty protected headers
    ///
    /// The [JWS RFC] allows for the protected header to be empty, and instead
    /// supply all necessary parameters in the unprotected header. By
    /// default, the `jose` crate will overwrite the `alg` field (and
    /// optionally `kid` field) in the protected header, with the signing
    /// algorithm used in the signing operation.
    /// To achieve that the `alg` field is set on the unprotected header, one
    /// must set the `alg`
    /// field to `HeaderValue::Protected(JsonWebSigningAlgorithm::None)`
    /// manually.
    ///
    /// However, you must note, that this feature is not supported for the
    /// [`Compact`](crate::format::Compact) format, becuase that format can only
    /// have a protected header.
    ///
    /// ```
    /// # use jose::{format::*, jws::*, header::HeaderValue, jwa::*};
    /// # fn main() {
    /// let jws = JsonWebSignature::<JsonFlattened, _>::builder()
    ///     .header(|b| b.algorithm(HeaderValue::Unprotected(JsonWebSigningAlgorithm::None)))
    ///     .build(())
    ///     .unwrap();
    /// # }
    /// ```
    ///
    /// [JWS RFC]: <https://datatracker.ietf.org/doc/html/rfc7515>
    // TODO: Add support for JsonGeneral
    pub fn header<
        CB: Fn(JoseHeaderBuilder<F, header::Jws>) -> JoseHeaderBuilder<F, header::Jws>,
    >(
        mut self,
        callback: CB,
    ) -> Self {
        // when there was an error setting the previous header,
        // do not overwrite the header value, because we want
        // to keep the error and report it in the `build` method
        if self.header.is_err() {
            return self;
        }

        let builder = JoseHeader::<F, header::Jws>::builder()
            .algorithm(HeaderValue::Protected(JsonWebSigningAlgorithm::None));
        let builder = callback(builder);

        F::finalize_jws_header_builder(&mut self.header, builder);

        self
    }

    /// Finalizes this builder and returns the creates [`JsonWebSignature`].
    ///
    /// # Errors
    ///
    /// Fails if the supplied header parameters were invalid.
    pub fn build<T>(self, payload: T) -> Result<JsonWebSignature<F, T>, JoseHeaderBuilderError> {
        Ok(JsonWebSignature::new(self.header?, payload))
    }
}
