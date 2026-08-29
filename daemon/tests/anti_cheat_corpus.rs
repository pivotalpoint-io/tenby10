//! Anti-cheat fixture corpus (issue #120).
//!
//! Loads every trace in `tests/fixtures/`, runs the real entropy detector over
//! it, and asserts the verdict matches the trace's known label. Drop a new
//! `*.json` (captured with `daemon --capture-trace`) in that directory and it is
//! picked up automatically.

use daemon::fixtures::{Trace, is_flagged, matches_expectation, should_flag};
use std::path::Path;

fn load_all() -> Vec<(String, Trace)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut traces = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixtures dir should exist") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let data = std::fs::read_to_string(&path).unwrap();
        let trace: Trace = serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("fixture {} is not a valid Trace: {}", name, e));
        traces.push((name, trace));
    }
    traces
}

#[test]
fn corpus_traces_classify_as_labelled() {
    let traces = load_all();
    assert!(!traces.is_empty(), "no fixtures found");

    let mut mismatches = Vec::new();
    let mut captured = 0usize;
    for (name, trace) in &traces {
        if trace.is_captured() {
            captured += 1;
        }
        if !matches_expectation(trace) {
            mismatches.push(format!(
                "  {name}: label={:?} should_flag={} but detector flagged={}",
                trace.label,
                should_flag(trace),
                is_flagged(trace),
            ));
        }
    }

    // Surface the make-up of the corpus so a green run is never mistaken for
    // "verified against real tools" while it is still synthetic-only.
    eprintln!(
        "[corpus] {} traces: {} captured / {} synthetic",
        traces.len(),
        captured,
        traces.len() - captured,
    );
    if captured == 0 {
        eprintln!(
            "[corpus] WARNING: 0 captured traces — the detector is only checked against \
             hand-authored samples. Add real captures (daemon --capture-trace) to break the \
             circularity (issue #120)."
        );
    }

    assert!(
        mismatches.is_empty(),
        "detector disagreed with {} labelled trace(s):\n{}",
        mismatches.len(),
        mismatches.join("\n"),
    );
}
