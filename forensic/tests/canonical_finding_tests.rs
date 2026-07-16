#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::redundant_closure_for_method_calls
)]
//! mbr-forensic anomalies normalize onto the canonical `forensicnomicon::report`
//! model via the `Observation` producer trait.

use forensicnomicon::report::{Category, Observation, Source};
use mbr_partition_forensic::{Anomaly, AnomalyKind};

fn src() -> Source {
    Source {
        analyzer: "mbr-forensic".to_string(),
        scope: "MBR".to_string(),
        version: None,
    }
}

#[test]
fn anomaly_converts_to_a_canonical_finding() {
    let a = Anomaly::new(AnomalyKind::NoBootablePartition, 0x1be);
    let f = a.to_finding(src());

    assert_eq!(f.code, "MBR-BOOT-NONE");
    assert!(f.severity.is_some(), "mbr anomalies are always graded");
    // Category is derived from the code by the default classifier.
    assert_eq!(f.category, Category::Threat);
    // The anomaly's byte offset rides along as evidence.
    assert_eq!(f.evidence[0].field, "offset");
    assert_eq!(f.source.analyzer, "mbr-forensic");
}

#[test]
fn unknown_boot_code_finding_surfaces_raw_bytes_as_evidence() {
    // An "unrecognised" finding must hand the investigator the actual offending
    // value: the UnknownBootCode kind pushes the raw hex as a second evidence
    // field alongside the byte offset.
    let a = Anomaly::new(
        AnomalyKind::UnknownBootCode {
            boot_code_hex: "de ad be ef".to_string(),
        },
        0,
    );
    let f = a.to_finding(src());

    assert_eq!(f.code, "MBR-BOOT-UNKNOWN");
    assert_eq!(f.evidence[0].field, "offset");
    let bc = f
        .evidence
        .iter()
        .find(|e| e.field == "boot_code")
        .expect("UnknownBootCode must carry a boot_code evidence field");
    assert_eq!(bc.value, "de ad be ef");
}
