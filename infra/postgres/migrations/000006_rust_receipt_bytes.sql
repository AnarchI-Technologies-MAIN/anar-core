BEGIN;
ALTER TABLE anar_core.decision_receipts ADD COLUMN rust_receipt_bytes bytea, ADD COLUMN rust_receipt_sha256 bytea;
ALTER TABLE anar_core.decision_receipts ADD CONSTRAINT rust_receipt_hash_length CHECK (rust_receipt_sha256 IS NULL OR octet_length(rust_receipt_sha256) = 32);
COMMIT;
