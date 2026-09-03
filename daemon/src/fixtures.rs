//! Anti-cheat fixture corpus (issue #119).
//!
//! The entropy heuristics are unit-tested with hand-authored samples — the
//! detector and its test data written together, which proves the functions do
//! what we designed, not that they catch what *real* cheat tools emit. This
//! module runs the real detectors over recorded traces so that circularity can
//! be broken with **captured** data.
//!
//! A [`Trace`] is a labelled recording of input timing (keyboard) or cursor
//! motion (mouse), tagged with its `source`:
//!   - `"captured"` — recorded from a real tool / real human via
//!     `daemon --capture-trace` (see `daemon/tests/README.md`);
//!   - `"synthetic"` — hand-authored; useful for format examples and a harness
//!     smoke test, but it does **not** break the circularity.
//!
//! The corpus test (`tests/anti_cheat_corpus.rs`) loads every fixture, runs the
//! matching detector, and asserts the verdict matches the label. It also reports
//! how many traces are captured vs. synthetic, so a green run is never mistaken
//! for "verified against real tools" while the corpus is still synthetic-only.

use serde::{Deserialize, Serialize};

/// What a trace is known to be. `Macro`/`Jiggler` must be flagged by the
/// detector; `Human` must not.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Label {
    Macro,
    Jiggler,
    Human,
}

/// The recorded samples: keyboard inter-key intervals (ms) or mouse
/// `(x, y, timestamp_ms)` positions.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Samples {
    Keyboard { intervals: Vec<i64> },
    Mouse { positions: Vec<(f64, f64, i64)> },
}

fn default_source() -> String {
    "synthetic".to_string()
}

/// A labelled input recording.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Trace {
    pub label: Label,
    /// `"captured"` (from a real tool/human) or `"synthetic"` (hand-authored).
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub note: String,
    pub samples: Samples,
}

impl Trace {
    /// Whether this trace was recorded from real input (vs. hand-authored).
    pub fn is_captured(&self) -> bool {
        self.source == "captured"
    }
}

/// Whether the entropy detector flags this trace as automation.
pub fn is_flagged(trace: &Trace) -> bool {
    match &trace.samples {
        Samples::Keyboard { intervals } => crate::entropy::is_keyboard_macro(intervals),
        Samples::Mouse { positions } => crate::entropy::is_mouse_jiggler(positions),
    }
}

/// Whether the label means the detector *should* flag this trace.
pub fn should_flag(trace: &Trace) -> bool {
    matches!(trace.label, Label::Macro | Label::Jiggler)
}

/// Whether the detector's verdict matches the trace's known label.
pub fn matches_expectation(trace: &Trace) -> bool {
    is_flagged(trace) == should_flag(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_and_expectation() {
        let json = r#"{
            "label": "macro",
            "source": "synthetic",
            "note": "constant 100ms",
            "samples": { "kind": "keyboard", "intervals": [100,100,101,100,99,100,100,101] }
        }"#;
        let trace: Trace = serde_json::from_str(json).unwrap();
        assert_eq!(trace.label, Label::Macro);
        assert!(!trace.is_captured());
        assert!(should_flag(&trace));
        assert!(is_flagged(&trace), "a constant-interval macro is flagged");
        assert!(matches_expectation(&trace));

        // Serializes back to a parseable trace.
        let re: Trace = serde_json::from_str(&serde_json::to_string(&trace).unwrap()).unwrap();
        assert_eq!(re.label, Label::Macro);
    }

    #[test]
    fn test_human_trace_not_flagged() {
        let trace = Trace {
            label: Label::Human,
            source: "synthetic".to_string(),
            note: String::new(),
            samples: Samples::Keyboard {
                intervals: vec![120, 150, 135, 200, 180, 145, 160, 220, 110, 130],
            },
        };
        assert!(!should_flag(&trace));
        assert!(!is_flagged(&trace));
        assert!(matches_expectation(&trace));
    }

    #[test]
    fn test_source_defaults_to_synthetic() {
        // A fixture without an explicit source must not be counted as captured.
        let json = r#"{ "label": "human",
            "samples": { "kind": "mouse", "positions": [[0.0,0.0,0],[5.0,3.0,50]] } }"#;
        let trace: Trace = serde_json::from_str(json).unwrap();
        assert_eq!(trace.source, "synthetic");
        assert!(!trace.is_captured());
    }
}
