#[cfg(feature = "postgres")]
use anar_core_engine::{CandidateDecision, DecisionReceipt, FinalizationState, ReceiptMaterial};
#[cfg(feature = "postgres")]
use anar_core_types::StableId;
#[cfg(feature = "postgres")]
use sqlx::{Connection, PgConnection, Row};
#[cfg(feature = "postgres")]
use uuid::Uuid;

/// SQLx finalization seam. PostgreSQL owns locking/revalidation/sequence assignment;
/// the typed Rust receipt is written before the same transaction commits.
#[cfg(feature = "postgres")]
pub async fn finalize_with_sqlx(
    connection: &mut PgConnection,
    candidate: &CandidateDecision,
    material: ReceiptMaterial,
    idempotency_key: &str,
    cal_semantic_hash: &[u8],
    authority_context_id: StableId,
) -> Result<DecisionReceipt, sqlx::Error> {
    let mut tx = connection.begin().await?;
    let row = sqlx::query("SELECT * FROM anar_core.finalize_decision_rehearsal($1::uuid,$2::uuid,$3::uuid,$4::text,$5::uuid,$6::uuid,$7::uuid,$8::uuid,$9::uuid,$10::text,$11::integer,$12::text,$13::bytea,$14::text,$15::text[],$16::bytea,$17::bytea,$18::bytea,$19::bytea,$20::bytea,$21::jsonb,$22::bigint,$23::bigint,$24::bigint,$25::bigint,$26::bigint,$27::bigint,$28::bigint,$29::bigint)")
        .bind(Uuid::from_bytes(*material.decision_id.as_bytes())).bind(Uuid::from_bytes(*material.receipt_id.as_bytes())).bind(Uuid::from_bytes(*candidate.request_id.as_bytes()))
        .bind(idempotency_key).bind(Uuid::from_bytes(*candidate.principal_id.as_bytes())).bind(Uuid::from_bytes(*candidate.organization_id.as_bytes()))
        .bind(Uuid::from_bytes(*candidate.membership_id.as_bytes())).bind(Uuid::from_bytes(*candidate.authenticator_id.as_bytes())).bind(Uuid::from_bytes(*authority_context_id.as_bytes()))
        .bind(candidate.capability_id.as_str()).bind(candidate.capability_version as i32)
        .bind("authority.membership.revoke").bind(cal_semantic_hash).bind("ALLOW")
        .bind(candidate.reason_codes.iter().map(|r| r.as_str()).collect::<Vec<_>>())
        .bind(candidate.request_semantic_hash.as_bytes()).bind(candidate.evaluation_snapshot_hash.as_bytes())
        .bind(candidate.policy_bundle_hash.as_bytes()).bind(candidate.dependency_bundle.digest().as_bytes())
        .bind(serde_json::to_value(candidate.dependency_bundle.dependencies()).map_err(|e| sqlx::Error::Decode(Box::new(e)))?)
        .bind(candidate.evaluated_generations.principal_generation).bind(candidate.evaluated_generations.organization_generation)
        .bind(candidate.evaluated_generations.membership_generation).bind(candidate.evaluated_generations.credential_revision)
        .bind(candidate.evaluated_generations.credential_revision).bind(candidate.evaluated_generations.principal_global_revocation_epoch)
        .bind(candidate.evaluated_generations.organization_revocation_epoch).bind(material.issued_at_epoch_ms)
        .fetch_one(&mut *tx).await?;
    let finalization = FinalizationState {
        principal_id: candidate.principal_id,
        organization_id: candidate.organization_id,
        membership_id: candidate.membership_id,
        authenticator_id: candidate.authenticator_id,
        principal_global_sequence: row.try_get("principal_global_sequence")?,
        organization_decision_sequence: row.try_get("organization_decision_sequence")?,
        principal_global_revocation_epoch: candidate
            .evaluated_generations
            .principal_global_revocation_epoch,
        organization_revocation_epoch: candidate
            .evaluated_generations
            .organization_revocation_epoch,
        live_generations: candidate.evaluated_generations.clone(),
    };
    let receipt = DecisionReceipt::issue(candidate, &finalization, material)
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    sqlx::query("UPDATE anar_core.decision_receipts SET rust_receipt_bytes=, rust_receipt_sha256= WHERE receipt_id=")
        .bind(&receipt.canonical_bytes).bind(receipt.receipt_hash.as_bytes()).bind(Uuid::from_bytes(*receipt.receipt_id.as_bytes()))
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(receipt)
}
