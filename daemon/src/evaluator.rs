use crate::entropy::{is_keyboard_macro, is_mouse_jiggler};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityClassification {
    Active,        // Green Focus
    PassiveReview, // Yellow Focus (Passive reading/designing)
    Meeting,       // Blue Focus (Active meetings without inputs)
    Idle,          // Red Idle
    Tampered,      // Anti-cheat triggered
    Distracted,    // Red Waste (Blacklisted apps)
}

pub struct ActivityEvaluator {}

impl Default for ActivityEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LiveEvaluationContext<'a> {
    pub keystroke_count: u32,
    pub mouse_click_count: u32,
    pub scroll_event_count: u32,
    pub active_app: &'a str,
    pub active_title: &'a str,
    pub mouse_positions: &'a [(f64, f64, i64)],
    pub key_intervals: &'a [i64],
    pub was_recently_active: bool,
    pub distracting_apps: &'a str,
    pub productive_apps: &'a str,
    pub meeting_apps: &'a str,
}

pub struct StoredEvaluationContext<'a> {
    pub keystroke_count: u32,
    pub mouse_click_count: u32,
    pub scroll_event_count: u32,
    pub active_app: &'a str,
    pub active_title: &'a str,
    pub low_entropy: bool,
    pub was_recently_active: bool,
    pub distracting_apps: &'a str,
    pub productive_apps: &'a str,
    pub meeting_apps: &'a str,
}

/// Whether `title` contains `keyword`. Single alphanumeric keywords must match a
/// whole word (so "meeting" does not match `meet`, "zoomed" does not match
/// `zoom`); punctuated / multi-token keywords (e.g. `slack | huddle`) keep
/// substring matching since they are already specific. Both args are lowercase.
fn title_matches_keyword(title: &str, keyword: &str) -> bool {
    if keyword.chars().any(|c| !c.is_ascii_alphanumeric()) {
        return title.contains(keyword);
    }
    title
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| word == keyword)
}

/// Detect a browser-hosted meeting from its title alone (the only signal we have
/// — we do not capture the address-bar URL): a `meet.google.com` reference or a
/// Google Meet `xxx-xxxx-xxx` code. `title` is lowercase.
fn title_has_meeting_url(title: &str) -> bool {
    if title.contains("meet.google.com") {
        return true;
    }
    // Google Meet code: three lowercase-letter groups of length 3-4-3.
    title
        .split(|c: char| !(c.is_ascii_lowercase() || c == '-'))
        .any(|tok| {
            let parts: Vec<&str> = tok.split('-').collect();
            parts.len() == 3
                && parts[0].len() == 3
                && parts[1].len() == 4
                && parts[2].len() == 3
                && parts
                    .iter()
                    .all(|p| p.chars().all(|c| c.is_ascii_lowercase()))
        })
}

/// Whether the active window represents a genuine meeting (issue #97). Native
/// meeting clients are matched by application name (hard to spoof); browser-hosted
/// meetings are matched by a whole-word title keyword or a Meet URL/code, so a
/// document merely titled "Meeting notes" or a window renamed to contain "zoom"
/// is not mistaken for one. This hardens the spoof surface the ADR-0002 no-input
/// cap must absorb; it does NOT prove a human is present in a live call (see #94).
/// `app_lower` / `title_lower` are lowercase.
fn is_meeting_context(app_lower: &str, title_lower: &str, meeting_apps: &str) -> bool {
    for keyword in meeting_apps
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
    {
        // Native client: the running application itself matches (trusted name).
        if app_lower.contains(&keyword) {
            return true;
        }
        // Browser tab / window title: whole-word keyword match.
        if title_matches_keyword(title_lower, &keyword) {
            return true;
        }
    }
    // Browser-hosted meeting recognizable only by its URL/code.
    title_has_meeting_url(title_lower)
}

impl ActivityEvaluator {
    pub fn new() -> Self {
        ActivityEvaluator {}
    }

    pub fn evaluate_minute(&self, ctx: &LiveEvaluationContext<'_>) -> ActivityClassification {
        // 1. Anti-Cheat Check: Detect automated mouse jigglers or typing macros
        let jiggler_detected = is_mouse_jiggler(ctx.mouse_positions);
        let macro_detected = is_keyboard_macro(ctx.key_intervals);

        if jiggler_detected || macro_detected {
            return ActivityClassification::Tampered;
        }

        // 1.5 Distraction Check: If active window matches any blacklisted distracting keywords
        let app_lower = ctx.active_app.to_lowercase();
        let title_lower = ctx.active_title.to_lowercase();
        let is_distracted = ctx
            .distracting_apps
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .any(|distraction| {
                app_lower.contains(&distraction) || title_lower.contains(&distraction)
            });

        if is_distracted {
            return ActivityClassification::Distracted;
        }

        // 2. Active Focus Check: Active user input exists and is clean
        let has_input =
            ctx.keystroke_count > 0 || ctx.mouse_click_count > 0 || ctx.scroll_event_count > 0;
        if has_input {
            return ActivityClassification::Active;
        }

        // 2.5. Meeting Check: No inputs, but active window is a genuine meeting (#97).
        if is_meeting_context(&app_lower, &title_lower, ctx.meeting_apps) {
            return ActivityClassification::Meeting;
        }

        // 3. Passive Review Check: No inputs, but app is on whitelist and user was recently coding/designing
        let app_lower = ctx.active_app.to_lowercase();
        let title_lower = ctx.active_title.to_lowercase();
        let is_productivity_app = ctx
            .productive_apps
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .any(|app| app_lower.contains(&app) || title_lower.contains(&app));

        if is_productivity_app && ctx.was_recently_active {
            return ActivityClassification::PassiveReview;
        }

        // 4. Default state: Idle
        ActivityClassification::Idle
    }

    pub fn evaluate_stored_minute(
        &self,
        ctx: &StoredEvaluationContext<'_>,
    ) -> ActivityClassification {
        if ctx.low_entropy {
            return ActivityClassification::Tampered;
        }

        let app_lower = ctx.active_app.to_lowercase();
        let title_lower = ctx.active_title.to_lowercase();
        let is_distracted = ctx
            .distracting_apps
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .any(|distraction| {
                app_lower.contains(&distraction) || title_lower.contains(&distraction)
            });

        if is_distracted {
            return ActivityClassification::Distracted;
        }

        // 2. Active Focus Check
        let has_input =
            ctx.keystroke_count > 0 || ctx.mouse_click_count > 0 || ctx.scroll_event_count > 0;
        if has_input {
            return ActivityClassification::Active;
        }

        // 2.5. Meeting Check (#97)
        if is_meeting_context(&app_lower, &title_lower, ctx.meeting_apps) {
            return ActivityClassification::Meeting;
        }

        // 3. Passive Review Check
        let app_lower = ctx.active_app.to_lowercase();
        let title_lower = ctx.active_title.to_lowercase();
        let is_productivity_app = ctx
            .productive_apps
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .any(|app| app_lower.contains(&app) || title_lower.contains(&app));

        if is_productivity_app && ctx.was_recently_active {
            return ActivityClassification::PassiveReview;
        }

        ActivityClassification::Idle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_focus() {
        let evaluator = ActivityEvaluator::new();
        let ctx = LiveEvaluationContext {
            keystroke_count: 10,
            mouse_click_count: 2,
            scroll_event_count: 0,
            active_app: "AnyApp",
            active_title: "AnyTitle",
            mouse_positions: &[(0.0, 0.0, 100), (1.0, 1.0, 200)], // Valid movement
            key_intervals: &[100, 150, 200],                      // Valid intervals
            was_recently_active: false,
            distracting_apps: "twitter,reddit",
            productive_apps: "vscode, cursor",
            meeting_apps: "zoom,meet",
        };
        assert_eq!(
            evaluator.evaluate_minute(&ctx),
            ActivityClassification::Active
        );
    }

    #[test]
    fn test_passive_review() {
        let evaluator = ActivityEvaluator::new();
        let ctx = LiveEvaluationContext {
            keystroke_count: 0,
            mouse_click_count: 0,
            scroll_event_count: 0,
            active_app: "VSCode",
            active_title: "evaluator.rs",
            mouse_positions: &[],
            key_intervals: &[],
            was_recently_active: true,
            distracting_apps: "twitter,reddit",
            productive_apps: "vscode, cursor",
            meeting_apps: "zoom,meet",
        };
        assert_eq!(
            evaluator.evaluate_minute(&ctx),
            ActivityClassification::PassiveReview
        );
    }

    #[test]
    fn test_idle() {
        let evaluator = ActivityEvaluator::new();
        let ctx = LiveEvaluationContext {
            keystroke_count: 0,
            mouse_click_count: 0,
            scroll_event_count: 0,
            active_app: "AnyApp",
            active_title: "AnyTitle",
            mouse_positions: &[],
            key_intervals: &[],
            was_recently_active: false,
            distracting_apps: "twitter,reddit",
            productive_apps: "vscode, cursor",
            meeting_apps: "zoom,meet",
        };
        assert_eq!(
            evaluator.evaluate_minute(&ctx),
            ActivityClassification::Idle
        );
    }

    #[test]
    fn test_distraction_idle() {
        let evaluator = ActivityEvaluator::new();
        // Even with active input, if the app is a distraction, it should be Distracted.
        let ctx = LiveEvaluationContext {
            keystroke_count: 10,
            mouse_click_count: 2,
            scroll_event_count: 0,
            active_app: "Twitter",
            active_title: "Home",
            mouse_positions: &[(0.0, 0.0, 100), (1.0, 1.0, 200)],
            key_intervals: &[100, 150, 200],
            was_recently_active: true,
            distracting_apps: "twitter,reddit",
            productive_apps: "vscode, cursor",
            meeting_apps: "zoom,meet",
        };
        assert_eq!(
            evaluator.evaluate_minute(&ctx),
            ActivityClassification::Distracted
        );
    }

    #[test]
    fn test_tampered_jiggler() {
        let evaluator = ActivityEvaluator::new();
        let mut positions = Vec::new();
        for i in 0..15 {
            positions.push((i as f64 * 10.0, i as f64 * 10.0, i * 100));
        }

        let ctx = LiveEvaluationContext {
            keystroke_count: 0,
            mouse_click_count: 0,
            scroll_event_count: 0,
            active_app: "VSCode",
            active_title: "evaluator.rs",
            mouse_positions: &positions,
            key_intervals: &[],
            was_recently_active: true,
            distracting_apps: "",
            productive_apps: "vscode, cursor",
            meeting_apps: "zoom,meet",
        };
        assert_eq!(
            evaluator.evaluate_minute(&ctx),
            ActivityClassification::Tampered
        );
    }

    #[test]
    fn test_tampered_keyboard_macro_overrides_input() {
        // A macro produces a high keystroke count AND near-constant timing. The
        // anti-cheat check runs FIRST, so the minute is Tampered, not Active —
        // i.e. faking input via a macro earns no active credit.
        let evaluator = ActivityEvaluator::new();
        let ctx = LiveEvaluationContext {
            keystroke_count: 240, // lots of "typing"
            mouse_click_count: 0,
            scroll_event_count: 0,
            active_app: "VSCode",
            active_title: "evaluator.rs",
            mouse_positions: &[],
            key_intervals: &[100, 100, 101, 100, 99, 100, 101, 100], // metronomic
            was_recently_active: true,
            distracting_apps: "",
            productive_apps: "vscode, cursor",
            meeting_apps: "zoom,meet",
        };
        assert_eq!(
            evaluator.evaluate_minute(&ctx),
            ActivityClassification::Tampered
        );
    }

    // --- meeting matching hardening (#97) ---

    fn no_input_ctx<'a>(
        app: &'a str,
        title: &'a str,
        meeting_apps: &'a str,
    ) -> LiveEvaluationContext<'a> {
        LiveEvaluationContext {
            keystroke_count: 0,
            mouse_click_count: 0,
            scroll_event_count: 0,
            active_app: app,
            active_title: title,
            mouse_positions: &[],
            key_intervals: &[],
            was_recently_active: false,
            distracting_apps: "",
            productive_apps: "vscode, cursor",
            meeting_apps,
        }
    }

    #[test]
    fn test_title_matches_keyword_is_whole_word() {
        assert!(title_matches_keyword("google meet", "meet"));
        assert!(title_matches_keyword("zoom meeting", "zoom"));
        assert!(!title_matches_keyword("meeting notes", "meet")); // not the word "meet"
        assert!(!title_matches_keyword("myzoomrecording.mp4", "zoom")); // substring only
        // Punctuated/multi-token keywords keep substring matching.
        assert!(title_matches_keyword(
            "acme — slack | huddle",
            "slack | huddle"
        ));
    }

    #[test]
    fn test_title_has_meeting_url() {
        assert!(title_has_meeting_url("abc-defg-hij"));
        assert!(title_has_meeting_url("meet - abc-defg-hij"));
        assert!(title_has_meeting_url(
            "https://meet.google.com/abc-defg-hij"
        ));
        assert!(!title_has_meeting_url("2024-project-plan")); // digits, not a code
        assert!(!title_has_meeting_url("meeting notes")); // no code
    }

    #[test]
    fn test_meeting_matched_by_native_app() {
        let e = ActivityEvaluator::new();
        assert_eq!(
            e.evaluate_minute(&no_input_ctx("zoom.us", "Zoom", "zoom, meet, teams")),
            ActivityClassification::Meeting
        );
    }

    #[test]
    fn test_meeting_matched_by_meet_code_without_keyword() {
        // meeting_apps lacks "meet"; only the Meet URL/code identifies the tab.
        let e = ActivityEvaluator::new();
        assert_eq!(
            e.evaluate_minute(&no_input_ctx(
                "Google Chrome",
                "xyz-qwrt-lmn",
                "zoom, teams"
            )),
            ActivityClassification::Meeting
        );
    }

    #[test]
    fn test_meeting_notes_document_is_not_a_meeting() {
        // "Meeting notes" must not be treated as a meeting just because it
        // contains "meet". No input, non-productive app -> Idle.
        let e = ActivityEvaluator::new();
        assert_eq!(
            e.evaluate_minute(&no_input_ctx(
                "Notion",
                "Meeting notes - Q3",
                "zoom, meet, teams"
            )),
            ActivityClassification::Idle
        );
    }

    #[test]
    fn test_zoom_substring_in_filename_is_not_a_meeting() {
        let e = ActivityEvaluator::new();
        assert_eq!(
            e.evaluate_minute(&no_input_ctx("Finder", "myzoomrecording.mp4", "zoom, meet")),
            ActivityClassification::Idle
        );
    }
}
