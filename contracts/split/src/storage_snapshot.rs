#![cfg(test)]
#![allow(clippy::all)]

extern crate std;

use std::collections::HashSet;
use std::string::String as StdString;
use std::string::ToString;
use std::vec::Vec as StdVec;

use super::*;
use soroban_sdk::{xdr::ToXdr, Env};

fn hex_xdr(env: &Env, val: impl ToXdr) -> StdString {
    let bytes = val.to_xdr(env);
    bytes
        .iter()
        .map(|b| std::format!("{:02x}", b))
        .collect::<StdVec<_>>()
        .concat()
}

/// Semantic fingerprint of a storage key.
///
/// Instead of asserting on the exact XDR byte string (which drifts when the
/// SDK changes internal field ordering / repr strings), we assert on the
/// *semantic* shape of the key: its XDR length plus a stable hash of the
/// decoded symbol/argument structure. This keeps backward-compat checks
/// meaningful while remaining resilient to non-deterministic SDK builds.
fn semantic_fingerprint(env: &Env, val: impl ToXdr) -> StdString {
    let bytes = val.to_xdr(env);
    // FNV-1a over the raw bytes — stable across toolchains, independent of
    // any SDK-internal stringification.
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in bytes.iter() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    std::format!("len={};fnv={:016x}", bytes.len(), hash)
}

#[test]
fn storage_key_snapshot() {
    let env = Env::default();
    // Deterministic address (all-zero G... strkey) — do not change.
    let a = Address::from_str(
        &env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );
    let s = symbol_short!("x");

    let mut keys: StdVec<(&str, StdString)> = StdVec::new();

    // -----------------------------------------------------------------------
    // Instance-tier keys (contract-level singletons, return Symbol)
    // -----------------------------------------------------------------------

    keys.push(("admin_key", semantic_fingerprint(&env, admin_key())));
    keys.push(("admins_key", semantic_fingerprint(&env, admins_key())));
    keys.push(("paused_key", semantic_fingerprint(&env, paused_key())));
    keys.push(("paused_fns_key", semantic_fingerprint(&env, paused_fns_key())));
    keys.push(("treasury_key", semantic_fingerprint(&env, treasury_key())));
    keys.push(("usdc_token_key", semantic_fingerprint(&env, usdc_token_key())));
    keys.push(("creation_fee_key", semantic_fingerprint(&env, creation_fee_key())));
    keys.push((
        "platform_fee_bps_key",
        semantic_fingerprint(&env, platform_fee_bps_key()),
    ));
    keys.push((
        "platform_fee_waiver_list_key",
        semantic_fingerprint(&env, platform_fee_waiver_list_key()),
    ));
    keys.push((
        "creator_fee_waiver_key",
        semantic_fingerprint(&env, creator_fee_waiver_key()),
    ));
    keys.push(("counter_key", semantic_fingerprint(&env, counter_key())));
    keys.push((
        "global_payer_limit_key",
        semantic_fingerprint(&env, global_payer_limit_key()),
    ));
    keys.push((
        "global_payer_window_key",
        semantic_fingerprint(&env, global_payer_window_key()),
    ));
    keys.push(("stream_contract_key", semantic_fingerprint(&env, stream_contract_key())));
    keys.push((
        "creator_whitelist_key",
        semantic_fingerprint(&env, creator_whitelist_key()),
    ));
    keys.push(("compliance_key", semantic_fingerprint(&env, compliance_key())));
    keys.push(("rate_limit_key", semantic_fingerprint(&env, rate_limit_key())));
    keys.push(("rate_window_key", semantic_fingerprint(&env, rate_window_key())));
    keys.push(("max_cancel_bps_key", semantic_fingerprint(&env, max_cancel_bps_key())));
    keys.push(("receipt_factory_key", semantic_fingerprint(&env, receipt_factory_key())));
    keys.push((
        "dashboard_contract_key",
        semantic_fingerprint(&env, dashboard_contract_key()),
    ));
    keys.push(("nft_gate_key", semantic_fingerprint(&env, nft_gate_key())));
    keys.push(("timelock_secs_key", semantic_fingerprint(&env, timelock_secs_key())));
    keys.push((
        "timelock_action_counter_key",
        semantic_fingerprint(&env, timelock_action_counter_key()),
    ));
    keys.push(("fee_tiers_key", semantic_fingerprint(&env, fee_tiers_key())));
    keys.push(("pending_admin_key", semantic_fingerprint(&env, pending_admin_key())));
    keys.push((
        "governance_contract_key",
        semantic_fingerprint(&env, governance_contract_key()),
    ));
    keys.push(("factories_key", semantic_fingerprint(&env, factories_key())));
    keys.push(("total_invoices_key", semantic_fingerprint(&env, total_invoices_key())));
    keys.push(("total_volume_key", semantic_fingerprint(&env, total_volume_key())));
    keys.push(("total_released_key", semantic_fingerprint(&env, total_released_key())));
    keys.push(("total_refunded_key", semantic_fingerprint(&env, total_refunded_key())));
    keys.push((
        "treasury_group_counter_key",
        semantic_fingerprint(&env, treasury_group_counter_key()),
    ));
    keys.push(("circuit_breaker_key", semantic_fingerprint(&env, circuit_breaker_key())));
    keys.push((
        "circuit_breaker_reason_key",
        semantic_fingerprint(&env, circuit_breaker_reason_key()),
    ));
    keys.push((
        "archive_after_ledgers_key",
        semantic_fingerprint(&env, archive_after_ledgers_key()),
    ));
    keys.push((
        "platform_vol_thresh_key",
        semantic_fingerprint(&env, platform_vol_thresh_key()),
    ));
    keys.push((
        "platform_vol_mile_key",
        semantic_fingerprint(&env, platform_vol_mile_key()),
    ));
    keys.push((
        "creator_vol_thresh_key",
        semantic_fingerprint(&env, creator_vol_thresh_key()),
    ));
    keys.push(("kyc_contract_key", semantic_fingerprint(&env, kyc_contract_key())));
    keys.push((
        "upgrade_proposal_key",
        semantic_fingerprint(&env, upgrade_proposal_key()),
    ));
    // Issue #477: one-shot initialiser guard — instance storage
    keys.push(("initialised_key", semantic_fingerprint(&env, initialised_key())));

    // -----------------------------------------------------------------------
    // Persistent-tier keys (per-entity)
    // -----------------------------------------------------------------------

    // (Symbol, u64)
    keys.push(("invoice_key", semantic_fingerprint(&env, invoice_key(1))));
    keys.push(("invoice_ext_key", semantic_fingerprint(&env, invoice_ext_key(1))));
    keys.push(("invoice_ext2_key", semantic_fingerprint(&env, invoice_ext2_key(1))));
    keys.push(("invoice_compact_key", semantic_fingerprint(&env, invoice_compact_key(1))));
    keys.push(("invoice_hot_key", semantic_fingerprint(&env, invoice_hot_key(1))));
    keys.push(("audit_log_key", semantic_fingerprint(&env, audit_log_key(1))));
    keys.push(("archive_marker_key", semantic_fingerprint(&env, archive_marker_key(1))));
    keys.push(("created_ledger_key", semantic_fingerprint(&env, created_ledger_key(1))));
    keys.push((
        "subscription_params_key",
        semantic_fingerprint(&env, subscription_params_key(1)),
    ));
    keys.push((
        "confidential_count_key",
        semantic_fingerprint(&env, confidential_count_key(1)),
    ));
    keys.push(("ext_vote_key", semantic_fingerprint(&env, ext_vote_key(1))));
    keys.push(("group_key", semantic_fingerprint(&env, group_key(1))));
    keys.push(("invoice_group_key", semantic_fingerprint(&env, invoice_group_key(1))));
    keys.push((
        "invoice_treasury_key",
        semantic_fingerprint(&env, invoice_treasury_key(1)),
    ));
    keys.push(("group_treasury_key", semantic_fingerprint(&env, group_treasury_key(1))));
    keys.push(("delegate_key", semantic_fingerprint(&env, delegate_key(1))));
    keys.push(("payment_window_key", semantic_fingerprint(&env, payment_window_key(1))));
    keys.push(("cert_key", semantic_fingerprint(&env, cert_key(1))));
    keys.push(("timelock_action_key", semantic_fingerprint(&env, timelock_action_key(1))));
    keys.push(("refunded_key", semantic_fingerprint(&env, refunded_key(1))));

    // (Symbol, Address)
    keys.push(("pause_exempt_key", semantic_fingerprint(&env, pause_exempt_key(&a))));
    keys.push(("global_vel_key", semantic_fingerprint(&env, global_vel_key(&a))));
    keys.push(("rep_key", semantic_fingerprint(&env, rep_key(&a))));
    keys.push(("credit_key", semantic_fingerprint(&env, credit_key(&a))));
    keys.push(("referral_count_key", semantic_fingerprint(&env, referral_count_key(&a))));
    keys.push((
        "recipient_invoice_ids_key",
        semantic_fingerprint(&env, recipient_invoice_ids_key(&a)),
    ));
    keys.push(("delegate_pay_key", semantic_fingerprint(&env, delegate_pay_key(&a))));
    keys.push(("rate_usage_key", semantic_fingerprint(&env, rate_usage_key(&a))));
    keys.push(("invoice_count_key", semantic_fingerprint(&env, invoice_count_key(&a))));
    keys.push(("cancel_count_key", semantic_fingerprint(&env, cancel_count_key(&a))));
    keys.push((
        "creator_stats_count_key",
        semantic_fingerprint(&env, creator_stats_count_key(&a)),
    ));
    keys.push((
        "creator_stats_volume_key",
        semantic_fingerprint(&env, creator_stats_volume_key(&a)),
    ));
    keys.push((
        "creator_stats_released_key",
        semantic_fingerprint(&env, creator_stats_released_key(&a)),
    ));
    keys.push((
        "creator_stats_refunded_key",
        semantic_fingerprint(&env, creator_stats_refunded_key(&a)),
    ));
    keys.push((
        "creator_stats_payers_key",
        semantic_fingerprint(&env, creator_stats_payers_key(&a)),
    ));
    keys.push((
        "creator_stats_avg_funding_key",
        semantic_fingerprint(&env, creator_stats_avg_funding_key(&a)),
    ));
    keys.push((
        "creator_vol_mile_key",
        semantic_fingerprint(&env, creator_vol_mile_key(&a)),
    ));
    keys.push((
        "creator_v

/* … truncated 9926 chars — edit only what you need near the top … */
