#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryDisposition {
    Pseudonymized {
        key_version: String,
        pseudonym: String,
    },
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryPseudonymizer;

impl TelemetryPseudonymizer {
    pub fn accept_provider_result(
        raw_identifier: &str,
        key_version: &str,
        provider_result: Result<String, ()>,
    ) -> TelemetryDisposition {
        match provider_result {
            Ok(pseudonym)
                if !key_version.is_empty()
                    && !pseudonym.is_empty()
                    && pseudonym != raw_identifier =>
            {
                TelemetryDisposition::Pseudonymized {
                    key_version: key_version.to_owned(),
                    pseudonym,
                }
            }
            Ok(_) | Err(()) => TelemetryDisposition::Dropped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_outage_or_raw_fallback_drops_telemetry() {
        assert_eq!(
            TelemetryPseudonymizer::accept_provider_result("org-raw", "v1", Err(())),
            TelemetryDisposition::Dropped
        );
        assert_eq!(
            TelemetryPseudonymizer::accept_provider_result(
                "org-raw",
                "v1",
                Ok("org-raw".to_owned()),
            ),
            TelemetryDisposition::Dropped
        );
    }

    #[test]
    fn correlation_output_keeps_key_version() {
        assert_eq!(
            TelemetryPseudonymizer::accept_provider_result(
                "org-raw",
                "v7",
                Ok("hmac:v7:abc".to_owned()),
            ),
            TelemetryDisposition::Pseudonymized {
                key_version: "v7".to_owned(),
                pseudonym: "hmac:v7:abc".to_owned(),
            }
        );
    }
}
