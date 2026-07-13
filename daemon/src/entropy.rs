//! Anti-automation heuristics (ADR 0002 addendum).
//!
//! These are deliberately simple, deterministic **speed bumps**, not a wall. The
//! detector's source ships with the client, so a motivated cheater who reads it
//! can tune around any fixed rule. Their job is to stop *lazy / off-the-shelf*
//! automation — default mouse jigglers and naive keyboard macros. Adaptive,
//! behavioral detection that must stay hidden from the attacker belongs
//! server-side, not here.
//!
//! Design: score the **structure** of input (regularity, spatial confinement)
//! over a rolling multi-minute window, not raw magnitude. Jitter changes
//! magnitude but not structure, and a low-rate macro (e.g. one key/min) is only
//! visible once samples accumulate across minutes — which the per-minute window
//! this replaced could never see (issue #85). We bias toward **false negatives**
//! (miss a clever macro) over **false positives** (flag a real person), because
//! wrongly branding a genuine user a cheater is the worse failure for the product.

use std::f64::consts::PI;

/// Minimum inter-key intervals before the keyboard heuristic will classify.
const MACRO_MIN_SAMPLES: usize = 6;
/// A macro's inter-key timing is regular *relative to its own rate*: a low
/// coefficient of variation (stddev / mean) regardless of the absolute period.
/// Set conservatively so ordinary human typing (CoV ~0.2+) is not flagged.
const MACRO_MAX_COV: f64 = 0.15;
/// Strong fast path: near-constant intervals (also covers very tight macros
/// whose mean is tiny, where CoV is numerically noisy).
const MACRO_NEAR_CONSTANT_MS: f64 = 8.0;

/// Minimum cursor samples before the mouse heuristic will classify.
const JIGGLER_MIN_SAMPLES: usize = 10;
/// Constant-speed jiggler: velocity varies little relative to its mean.
const JIGGLER_MAX_VELOCITY_COV: f64 = 0.15;
/// Linear jiggler: heading barely changes between samples.
const JIGGLER_MAX_HEADING_SD: f64 = 0.05;
/// In-place jiggler: a lot of movement confined to a tiny region (anti-sleep
/// nudging). Bounding box smaller than this with a long path length is robotic.
const JIGGLER_CONFINED_BBOX_PX: f64 = 40.0;
const JIGGLER_CONFINED_MIN_PATH_PX: f64 = 500.0;
/// Confinement also requires a meaningful mean step: an anti-sleep jiggler nudges
/// the cursor by real amounts, whereas a hand resting on a trackpad produces many
/// sub-pixel samples (long total path, tiny steps). Without this floor, trackpad
/// rest-jitter would be a false positive — the worst failure for the product.
const JIGGLER_CONFINED_MIN_STEP_PX: f64 = 5.0;

/// Arithmetic mean (0.0 for an empty slice).
fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// Sample standard deviation. `None` with fewer than 2 values.
fn std_dev(values: &[f64]) -> Option<f64> {
    let count = values.len();
    if count < 2 {
        return None;
    }
    let m = mean(values);
    let variance = values
        .iter()
        .map(|&x| {
            let diff = x - m;
            diff * diff
        })
        .sum::<f64>()
        / (count - 1) as f64;
    Some(variance.sqrt())
}

/// Coefficient of variation (stddev / |mean|): dispersion normalized by scale,
/// so it is independent of the absolute rate. `None` with <2 samples or a
/// near-zero mean.
fn coefficient_of_variation(values: &[f64]) -> Option<f64> {
    let m = mean(values);
    if m.abs() < f64::EPSILON {
        return None;
    }
    std_dev(values).map(|sd| sd / m.abs())
}

/// Detect a keyboard macro from a rolling window of inter-key intervals (ms).
///
/// Flags input whose timing is regular *relative to its own rate*. Because this
/// is magnitude-independent it catches both jittered macros (which beat an
/// absolute stddev threshold) and low-rate macros such as one key/min (issue
/// #85), once the rolling window has accumulated enough samples. Idle gaps
/// between real typing bursts inflate the variation and protect genuine humans.
pub fn is_keyboard_macro(intervals: &[i64]) -> bool {
    if intervals.len() < MACRO_MIN_SAMPLES {
        return false; // Not enough timing data to classify.
    }
    let f64_intervals: Vec<f64> = intervals.iter().map(|&x| x as f64).collect();

    let sd = match std_dev(&f64_intervals) {
        Some(sd) => sd,
        None => return false,
    };
    // Near-constant intervals are unambiguously robotic.
    if sd < MACRO_NEAR_CONSTANT_MS {
        return true;
    }
    // Otherwise flag only if the intervals are tightly regular for their rate.
    match coefficient_of_variation(&f64_intervals) {
        Some(cov) => cov < MACRO_MAX_COV,
        None => false,
    }
}

/// Detect a mouse jiggler from a rolling window of `(x, y, timestamp_ms)`.
///
/// Three structural signals, any of which flags:
/// 1. **Confinement** — a long path confined to a tiny bounding box (nudging in
///    place to defeat sleep), which the previous "must be near-straight" rule
///    missed entirely for circular/random-in-place jigglers.
/// 2. **Constant speed + direction** — low velocity CoV and near-zero heading
///    change (linear/robotic motion).
/// 3. **Perfectly straight, sustained, constant speed** — high path length with
///    tortuosity ~1 and low velocity CoV. The velocity-CoV guard keeps genuine
///    fast human swipes (which accelerate/decelerate) from being flagged.
pub fn is_mouse_jiggler(positions: &[(f64, f64, i64)]) -> bool {
    if positions.len() < JIGGLER_MIN_SAMPLES {
        return false; // Not enough movement to classify.
    }

    let (mut min_x, mut min_y) = (f64::MAX, f64::MAX);
    let (mut max_x, mut max_y) = (f64::MIN, f64::MIN);
    for &(x, y, _) in positions {
        min_x = min_x.min(x);
        max_x = max_x.max(x);
        min_y = min_y.min(y);
        max_y = max_y.max(y);
    }

    let mut velocities = Vec::new();
    let mut headings = Vec::new();
    let mut total_length = 0.0;
    for i in 1..positions.len() {
        let (x1, y1, t1) = positions[i - 1];
        let (x2, y2, t2) = positions[i];
        let dx = x2 - x1;
        let dy = y2 - y1;
        let dist = (dx * dx + dy * dy).sqrt();
        total_length += dist;

        let dt = (t2 - t1) as f64;
        if dt > 0.0 {
            velocities.push(dist / dt);
            headings.push(dy.atan2(dx));
        }
    }
    if velocities.len() < 5 {
        return false;
    }

    // Signal 1: lots of chunky movement confined to a tiny region.
    let bbox = (max_x - min_x).max(max_y - min_y);
    let mean_step = total_length / (positions.len() - 1) as f64;
    if total_length > JIGGLER_CONFINED_MIN_PATH_PX
        && bbox < JIGGLER_CONFINED_BBOX_PX
        && mean_step > JIGGLER_CONFINED_MIN_STEP_PX
    {
        return true;
    }

    // Heading-change dispersion.
    let mut angle_diffs = Vec::new();
    for i in 1..headings.len() {
        let mut diff = headings[i] - headings[i - 1];
        while diff > PI {
            diff -= 2.0 * PI;
        }
        while diff < -PI {
            diff += 2.0 * PI;
        }
        angle_diffs.push(diff.abs());
    }
    let heading_sd = std_dev(&angle_diffs).unwrap_or(0.0);
    let velocity_cov = coefficient_of_variation(&velocities).unwrap_or(1.0);

    // Signal 2: constant speed AND constant direction.
    if velocity_cov < JIGGLER_MAX_VELOCITY_COV && heading_sd < JIGGLER_MAX_HEADING_SD {
        return true;
    }

    // Signal 3: perfectly straight, sustained, constant-speed motion.
    let (start_x, start_y, _) = positions[0];
    let (end_x, end_y, _) = positions[positions.len() - 1];
    let displacement = ((end_x - start_x).powi(2) + (end_y - start_y).powi(2)).sqrt();
    let tortuosity = if displacement > 1.0 {
        total_length / displacement
    } else {
        total_length
    };
    if tortuosity < 1.05 && total_length > 200.0 && velocity_cov < JIGGLER_MAX_VELOCITY_COV {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- keyboard ---

    #[test]
    fn test_human_keyboard() {
        // Varied intervals (CoV ~0.23) — not a macro.
        let intervals = vec![120, 150, 135, 200, 180, 145, 160, 220, 110, 130];
        assert!(!is_keyboard_macro(&intervals));
    }

    #[test]
    fn test_macro_keyboard_near_constant() {
        // Near-constant intervals (stddev < 8ms).
        let intervals = vec![100, 100, 101, 100, 100, 99, 100, 101, 100, 100];
        assert!(is_keyboard_macro(&intervals));
    }

    #[test]
    fn test_jittered_macro_flagged() {
        // ~200ms with ~20ms jitter: stddev ~17ms (> the old 10ms threshold, so
        // the previous detector MISSED this), but CoV ~0.085 — still robotic.
        let intervals = vec![180, 220, 195, 210, 185, 215, 200, 225, 175, 205];
        assert!(std_dev(&intervals.iter().map(|&x| x as f64).collect::<Vec<_>>()).unwrap() > 10.0);
        assert!(is_keyboard_macro(&intervals));
    }

    #[test]
    fn test_low_rate_macro_flagged() {
        // ~1 key/min macro. Impossible to see in a per-minute window (issue #85);
        // over the rolling window the intervals are ~60000ms with tiny variation.
        let intervals = vec![60000, 60300, 59800, 60100, 59950, 60200, 60050];
        assert!(is_keyboard_macro(&intervals));
    }

    #[test]
    fn test_human_typing_with_pauses_not_flagged() {
        // Real typing bursts separated by idle gaps — high variation, not a macro.
        let intervals = vec![110, 95, 130, 85_000, 120, 100, 90, 62_000, 115, 105];
        assert!(!is_keyboard_macro(&intervals));
    }

    #[test]
    fn test_keyboard_below_min_samples_not_classified() {
        let intervals = vec![100, 100, 100, 100, 100]; // 5 < MACRO_MIN_SAMPLES
        assert!(!is_keyboard_macro(&intervals));
    }

    // --- mouse ---

    #[test]
    fn test_human_mouse() {
        let positions = vec![
            (0.0, 0.0, 0),
            (10.0, 5.0, 50),
            (15.0, 20.0, 100),
            (30.0, 25.0, 180),
            (35.0, 40.0, 220),
            (50.0, 60.0, 300),
            (52.0, 61.0, 310),
            (70.0, 80.0, 400),
            (75.0, 100.0, 450),
            (80.0, 120.0, 500),
        ];
        assert!(!is_mouse_jiggler(&positions));
    }

    #[test]
    fn test_linear_jiggler_mouse() {
        // Constant speed in a straight line.
        let positions: Vec<_> = (0..15)
            .map(|i| (i as f64 * 10.0, i as f64 * 10.0, i * 100))
            .collect();
        assert!(is_mouse_jiggler(&positions));
    }

    #[test]
    fn test_in_place_jiggler_flagged() {
        // Random-looking nudging confined to a 20px box — long path, tiny bbox.
        // The old "must be near-straight" rule treated this winding path as human.
        let corners = [(0.0, 0.0), (20.0, 20.0), (0.0, 20.0), (20.0, 0.0)];
        let positions: Vec<_> = (0..28)
            .map(|i| {
                let (x, y) = corners[i % 4];
                (x, y, i as i64 * 100)
            })
            .collect();
        assert!(is_mouse_jiggler(&positions));
    }

    #[test]
    fn test_fast_human_swipe_not_flagged() {
        // A straight, fast swipe that accelerates — high velocity CoV keeps it
        // from being misread as a constant-speed linear jiggler.
        let positions = vec![
            (0.0, 0.0, 0),
            (5.0, 0.0, 50),
            (15.0, 0.0, 100),
            (35.0, 0.0, 150),
            (70.0, 0.0, 200),
            (120.0, 0.0, 250),
            (190.0, 0.0, 300),
            (280.0, 0.0, 350),
            (390.0, 0.0, 400),
            (520.0, 0.0, 450),
        ];
        assert!(!is_mouse_jiggler(&positions));
    }

    #[test]
    fn test_mouse_below_min_samples_not_classified() {
        let positions: Vec<_> = (0..5).map(|i| (i as f64, i as f64, i * 100)).collect();
        assert!(!is_mouse_jiggler(&positions));
    }

    // --- (C) Known-evasion characterization: pins the speed-bump boundary. ---
    // These assert what a source-reading cheater CAN still get away with, so the
    // limits are explicit and a regression in either direction fails loudly.

    #[test]
    fn test_high_jitter_macro_evades() {
        // ~200ms with ~45ms jitter → CoV ~0.22, above MACRO_MAX_COV. A macro with
        // enough jitter to look human evades the heuristic — by design; catching
        // it is the server-side layer's job, not this speed bump.
        let intervals = vec![160, 245, 175, 250, 155, 240, 200, 165, 235, 180];
        let cov =
            coefficient_of_variation(&intervals.iter().map(|&x| x as f64).collect::<Vec<_>>())
                .unwrap();
        assert!(
            cov > MACRO_MAX_COV,
            "sanity: this fixture is above the CoV cutoff"
        );
        assert!(!is_keyboard_macro(&intervals));
    }

    #[test]
    fn test_human_mimicking_jiggler_evades() {
        // A jiggler that replays wide-area, varied-speed motion (e.g. recorded
        // human input) looks human and is not flagged — the honest ceiling of a
        // client-side heuristic.
        let positions = vec![
            (0.0, 0.0, 0),
            (140.0, 30.0, 60),
            (155.0, 210.0, 130),
            (400.0, 250.0, 210),
            (410.0, 90.0, 250),
            (220.0, 400.0, 340),
            (600.0, 380.0, 430),
            (610.0, 120.0, 470),
            (330.0, 55.0, 560),
            (90.0, 300.0, 640),
        ];
        assert!(!is_mouse_jiggler(&positions));
    }

    // --- (D) False-positive corpus: genuine human patterns must NOT be flagged.
    // Flagging a real person is the worst failure for the product. ---

    #[test]
    fn test_hunt_and_peck_typist_not_flagged() {
        // Slow, irregular typing.
        let intervals = vec![800, 1200, 600, 2000, 900, 1500, 700, 1100];
        assert!(!is_keyboard_macro(&intervals));
    }

    #[test]
    fn test_fast_touch_typist_not_flagged() {
        // Fast typing still varies with digraph difficulty — CoV well above cutoff.
        let intervals = vec![90, 180, 120, 250, 110, 200, 95, 170, 130, 210];
        assert!(!is_keyboard_macro(&intervals));
    }

    #[test]
    fn test_gamer_key_mashing_not_flagged() {
        // Bursty WASD play: fast bursts separated by pauses.
        let intervals = vec![70, 65, 300, 80, 75, 280, 90, 68, 310, 72];
        assert!(!is_keyboard_macro(&intervals));
    }

    #[test]
    fn test_trackpad_rest_jitter_not_flagged() {
        // A hand resting on a trackpad: MANY sub-pixel samples confined to a tiny
        // area — a long total path in a small bbox, which naive confinement would
        // flag. The mean-step floor spares it. Without the fix in this change, this
        // test fails (false positive).
        let mut positions: Vec<(f64, f64, i64)> = Vec::new();
        let pattern: [(f64, f64); 6] = [
            (0.0, 0.0),
            (2.0, 1.0),
            (1.0, 2.0),
            (3.0, 0.0),
            (0.0, 3.0),
            (2.0, 2.0),
        ];
        for i in 0..300 {
            let (dx, dy) = pattern[i % pattern.len()];
            positions.push((dx, dy, i as i64 * 200)); // ~2px steps, ~600px total path
        }
        // Sanity: it IS confined and high-path (would trip naive confinement)...
        let total: f64 = (1..positions.len())
            .map(|i| {
                let (x1, y1, _) = positions[i - 1];
                let (x2, y2, _) = positions[i];
                ((x2 - x1).powi(2) + (y2 - y1).powi(2)).sqrt()
            })
            .sum();
        assert!(
            total > JIGGLER_CONFINED_MIN_PATH_PX,
            "sanity: long confined path"
        );
        // ...but the sub-pixel mean step keeps it from being flagged.
        assert!(!is_mouse_jiggler(&positions));
    }
}
