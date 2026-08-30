use anar_core_engine::{CandidateDecision, GenerationVector, ReasonCode, ReceiptMaterial};
use anar_core_runtime::postgres::finalize_with_sqlx;
use anar_core_types::{
    AuthorityDependencyRef, AuthorityDependencyType, AuthorityStatus, DecisionOutcome,
    DependencyBundle, RegisteredId, SemanticDigest, StableId,
};
use sqlx::{Connection, PgConnection, Row};

fn id(hex_last: u8) -> StableId {
    let mut b = [0u8; 16];
    b[15] = hex_last;
    StableId::from_bytes(b)
}
fn digest(byte: u8) -> SemanticDigest {
    SemanticDigest::from_bytes([byte; 32])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("DATABASE_URL")?;
    let mut c = PgConnection::connect(&url).await?;
    sqlx::query("SET anar.organization_id = '20000000-0000-4000-8000-000000000001'")
        .execute(&mut c)
        .await?;
    let dep = AuthorityDependencyRef {
        dependency_type: AuthorityDependencyType::PolicyBinding,
        dependency_id: id(1),
        organization_id: Some(id(1)),
        expected_generation: Some(3),
        expected_digest: None,
        expected_status: Some(AuthorityStatus::Active),
    };
    let candidate = CandidateDecision {
        request_id: id(1),
        principal_id: id(1),
        organization_id: id(1),
        membership_id: id(1),
        authenticator_id: id(1),
        capability_id: RegisteredId::new("authority.membership.revoke")?,
        capability_version: 1,
        outcome: DecisionOutcome::Allow,
        reason_codes: vec![ReasonCode::CurrentAuthorityProven],
        effective_envelope: None,
        request_semantic_hash: digest(0x21),
        evaluation_snapshot_hash: digest(0x22),
        policy_bundle_hash: digest(0x23),
        dependency_bundle: DependencyBundle::canonicalize([dep])?,
        evaluated_generations: GenerationVector {
            principal_generation: 2,
            membership_generation: 5,
            organization_generation: 4,
            policy_generation: 3,
            entitlement_generation: 3,
            credential_revision: 6,
            principal_global_revocation_epoch: 0,
            organization_revocation_epoch: 0,
        },
        evaluated_at_epoch_ms: 1800000000000,
    };
    let material = ReceiptMaterial {
        receipt_id: id(1),
        decision_id: id(1),
        authority_context_hash: digest(0x20),
        cal_semantic_hash: digest(0x11),
        evidence_bundle_hash: digest(0x24),
        effective_capability_hash: Some(SemanticDigest::ZERO),
        spec_sha256: digest(0x26),
        issued_at_epoch_ms: 1800000000000,
        valid_until_epoch_ms: 1900000000000,
    };
    let receipt = finalize_with_sqlx(
        &mut c,
        &candidate,
        material,
        "phase0.sqlx-probe",
        digest(0x11).as_bytes(),
        id(1),
    )
    .await?;
    let row=sqlx::query("SELECT rust_receipt_sha256, octet_length(rust_receipt_bytes) AS n FROM anar_core.decision_receipts WHERE receipt_id=").bind(uuid::Uuid::from_bytes(*receipt.receipt_id.as_bytes())).fetch_one(&mut c).await?;
    let stored: Vec<u8> = row.try_get("rust_receipt_sha256")?;
    let n: i32 = row.try_get("n")?;
    assert_eq!(stored, receipt.receipt_hash.as_bytes());
    assert!(n > 0);
    println!(
        "SQLX_RECEIPT_PARITY_PASS bytes={} hash={}",
        n, receipt.receipt_hash
    );
    Ok(())
}
