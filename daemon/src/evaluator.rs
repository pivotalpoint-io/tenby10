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

/// How strongly the active window identifies a live meeting. The distinction
/// exists because the ADR-0002 no-input streak cap has to absorb every false
/// meeting classification: evidence that survives a window rename earns a longer
/// silent streak than evidence that does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingConfidence {
    /// A native meeting client is frontmost, the title carries a platform's own
    /// structural shell, or a join transition was observed. None of these come
    /// from renaming a window.
    Strong,
    /// A `meeting_apps` keyword appears as a whole word in the title and nothing
    /// else corroborates it. User-extensible, and spoofable by renaming.
    Weak,
}

/// En/em dashes rewritten to ASCII so a platform's title shell matches whichever
/// dash it ships (Google Meet uses both `Meet - x` and `Meet – x`).
fn canonical_dashes(title: &str) -> String {
    title.replace(['\u{2013}', '\u{2014}'], "-")
}

/// Platform-authored title shells: the wrapper a meeting product puts around the
/// meeting's own name. Structural rather than keyword-based, so a document called
/// "Meet Sol, the new model" is not a meeting while `Meet - Standup` is.
/// `title_lower` is lowercase.
fn title_has_meeting_shell(title_lower: &str) -> bool {
    let t = canonical_dashes(title_lower);
    let t = t.trim();
    // Google Meet: "Meet - <topic>" / "Meet – <topic>".
    if t.starts_with("meet - ") {
        return true;
    }
    // Microsoft Teams, native and web: "<topic> | Microsoft Teams".
    if t.ends_with("| microsoft teams") || t.contains("| microsoft teams |") {
        return true;
    }
    // Zoom, including the launcher page and the native window.
    if t.ends_with("- zoom") || t.contains("zoom workplace") || t.contains("zoom meeting") {
        return true;
    }
    // Webex.
    if t.starts_with("webex |") || t.contains("cisco webex") || t.contains("webex meetings") {
        return true;
    }
    // Slack huddles.
    if t.contains("| huddle") || t.contains("huddle |") {
        return true;
    }
    false
}

/// A page that launches or joins a call, as opposed to the call itself. Seeing
/// one is what licenses [`MeetingSession`] to adopt the next title in the same
/// application: Zoom's web client titles its join page `Join from Zoom Workplace
/// app - Zoom` and then retitles the tab to the meeting topic alone, which
/// carries no platform marker of its own. `title_lower` is lowercase.
fn is_meeting_launcher(title_lower: &str) -> bool {
    const LAUNCHERS: [&str; 6] = [
        "join from zoom",
        "zoom workplace app",
        "meeting join",
        "join meeting",
        "launching meeting",
        "start your meeting",
    ];
    LAUNCHERS.iter().any(|p| title_lower.contains(p))
}

/// Compare titles across minutes without tripping over decoration the browser
/// adds and removes on its own: Chrome appends a speaker glyph while a tab plays
/// audio and prefixes an unread count. Lowercased, stripped of a leading `(n) `,
/// non-ASCII removed and whitespace collapsed — applied to both sides, so it only
/// has to be consistent, not pretty.
fn normalize_title(title_lower: &str) -> String {
    let mut t = title_lower.trim();
    if let Some(rest) = t.strip_prefix('(')
        && let Some((count, after)) = rest.split_once(')')
        && !count.is_empty()
        && count.chars().all(|c| c.is_ascii_digit())
    {
        t = after.trim_start();
    }
    t.chars()
        .filter(|c| c.is_ascii())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether the active window represents a genuine meeting, and how strongly
/// (issue #126, narrowing the #97 hardening). Native meeting clients are matched
/// by application name and platform title shells by structure, so a document
/// merely titled "Meeting notes" or a window renamed to contain "zoom" is not
/// mistaken for one. A bare title keyword still matches, at `Weak`. None of this
/// proves a human is present in a live call. `app_lower` / `title_lower` are
/// lowercase.
fn meeting_context(
    app_lower: &str,
    title_lower: &str,
    meeting_apps: &str,
) -> Option<MeetingConfidence> {
    let keywords = || {
        meeting_apps
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
    };

    // Native client: the running application itself matches (trusted name).
    if keywords().any(|k| app_lower.contains(&k)) {
        return Some(MeetingConfidence::Strong);
    }
    // Browser-hosted meeting identified by the platform's own title shell, or by
    // a Meet URL/code.
    if title_has_meeting_shell(title_lower) || title_has_meeting_url(title_lower) {
        return Some(MeetingConfidence::Strong);
    }
    // Browser tab / window title: whole-word keyword match, spoofable by rename.
    if keywords().any(|k| title_matches_keyword(title_lower, &k)) {
        return Some(MeetingConfidence::Weak);
    }
    None
}

/// Whether the active window represents a genuine meeting at all.
fn is_meeting_context(app_lower: &str, title_lower: &str, meeting_apps: &str) -> bool {
    meeting_context(app_lower, title_lower, meeting_apps).is_some()
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

/// How long a minute keeps granting passive-review credit after the last minute
/// of real input.
///
/// Deliberately 1. Crediting a thinking pause is contextual idle forgiveness
/// (ADR 0011), which grants it only when the pause is short *and* work genuinely
/// resumes afterwards. Widening this window would hand out the same credit with
/// neither condition attached, so a whitelisted app left open would earn for as
/// long as the window ran — a strictly weaker rule reached by a second route.
/// The constant exists so the horizon is stated once and every call site derives
/// it identically, which is what [`MinuteScanner`] is for.
pub const RECENT_ACTIVITY_WINDOW_MINUTES: u32 = 1;

/// A meeting session is dropped after this long without any corroboration, so a
/// tab left open on a finished call cannot keep earning indefinitely.
const MEETING_SESSION_MAX_MINUTES: u32 = 240;

/// A meeting being tracked across minutes.
struct MeetingSession {
    /// Lowercased application the meeting lives in.
    app: String,
    /// Normalized title being held (see [`normalize_title`]).
    title: String,
    confidence: MeetingConfidence,
    /// Whether a title change should be read as the call starting rather than as
    /// the meeting ending. Set only while the window is a launcher page, and the
    /// launcher re-anchors the session every minute it stays frontmost, so the
    /// change has to follow it immediately.
    adopt_next_title: bool,
    /// Minutes this session has been held without fresh direct evidence.
    held: u32,
}

/// Per-minute classifier state shared by every call site that scores minutes.
///
/// It carries the two things a single minute cannot know on its own: how
/// recently the user last supplied input, and whether an ongoing meeting explains
/// a window that no longer looks like one. Sharing one implementation is what
/// keeps a slot's total and its per-minute drill-down from disagreeing about the
/// same minute.
///
/// Callers read [`Self::was_recently_active`] before classifying a minute, then
/// hand the verdict back to [`Self::observe`], which may upgrade it and advances
/// the rolling state.
#[derive(Default)]
pub struct MinuteScanner {
    recent_active: u32,
    session: Option<MeetingSession>,
}

impl MinuteScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether input landed inside the recent-activity window. Feed this into
    /// [`LiveEvaluationContext::was_recently_active`] or its stored counterpart.
    pub fn was_recently_active(&self) -> bool {
        self.recent_active > 0
    }

    /// Advance the rolling state with this minute's window and verdict, and
    /// return the verdict the caller should record.
    ///
    /// A minute already credited is never downgraded here: only `Idle` is
    /// upgraded, and only when a meeting session covers it. The returned
    /// confidence is `Some` exactly when the verdict is `Meeting`, and selects
    /// which no-input streak cap applies to it.
    pub fn observe(
        &mut self,
        active_app: &str,
        active_title: &str,
        meeting_apps: &str,
        classification: ActivityClassification,
    ) -> (ActivityClassification, Option<MeetingConfidence>) {
        let app_lower = active_app.to_lowercase();
        let title_lower = active_title.to_lowercase();
        let direct = meeting_context(&app_lower, &title_lower, meeting_apps);
        let covering = self.advance_session(&app_lower, &title_lower, direct);

        let mut verdict = classification;
        if verdict == ActivityClassification::Idle && covering.is_some() {
            verdict = ActivityClassification::Meeting;
        }

        if verdict == ActivityClassification::Active {
            self.recent_active = RECENT_ACTIVITY_WINDOW_MINUTES;
        } else {
            self.recent_active = self.recent_active.saturating_sub(1);
        }

        let confidence = if verdict == ActivityClassification::Meeting {
            // A directly matched meeting reports its own strength even when no
            // session is being carried (the first minute of one).
            covering.or(direct)
        } else {
            None
        };
        (verdict, confidence)
    }

    /// Open, continue, adopt or drop the tracked meeting for this minute, and
    /// return the confidence covering it.
    fn advance_session(
        &mut self,
        app_lower: &str,
        title_lower: &str,
        direct: Option<MeetingConfidence>,
    ) -> Option<MeetingConfidence> {
        let title_norm = normalize_title(title_lower);

        if let Some(confidence) = direct {
            // Anchor on what we can see now. Only a launcher page licenses a
            // later title change to be read as the call starting.
            self.session = Some(MeetingSession {
                app: app_lower.to_string(),
                title: title_norm,
                confidence,
                adopt_next_title: is_meeting_launcher(title_lower),
                held: 0,
            });
            return Some(confidence);
        }

        if let Some(session) = self.session.as_mut()
            && session.app == app_lower
        {
            if session.title == title_norm {
                session.held += 1;
                if session.held <= MEETING_SESSION_MAX_MINUTES {
                    return Some(session.confidence);
                }
            } else if session.adopt_next_title {
                // The join page became the call. The meeting's own title carries
                // no platform marker, so this is the only point at which it can
                // be learned.
                session.title = title_norm;
                session.confidence = MeetingConfidence::Strong;
                session.adopt_next_title = false;
                session.held = 0;
                return Some(MeetingConfidence::Strong);
            }
        }

        self.session = None;
        None
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

    // --- browser-hosted meeting continuity (#126) ---
    //
    // The titles below are real ones observed on a developer machine, including
    // the Zoom web-client sequence that motivated this issue.

    const MEETINGS: &str = "zoom, meet, teams, webex, slack | huddle";

    /// Drive the scanner over consecutive minutes of `(app, title, keystrokes)`.
    /// `productive_apps` deliberately excludes browsers so passive-review credit
    /// cannot mask what the meeting logic is doing.
    fn drive(
        minutes: &[(&str, &str, u32)],
    ) -> Vec<(ActivityClassification, Option<MeetingConfidence>)> {
        let evaluator = ActivityEvaluator::new();
        let mut scanner = MinuteScanner::new();
        minutes
            .iter()
            .map(|(app, title, keys)| {
                let ctx = StoredEvaluationContext {
                    keystroke_count: *keys,
                    mouse_click_count: 0,
                    scroll_event_count: 0,
                    active_app: app,
                    active_title: title,
                    low_entropy: false,
                    was_recently_active: scanner.was_recently_active(),
                    distracting_apps: "youtube, netflix",
                    productive_apps: "vscode, cursor",
                    meeting_apps: MEETINGS,
                };
                let evaluated = evaluator.evaluate_stored_minute(&ctx);
                scanner.observe(app, title, MEETINGS, evaluated)
            })
            .collect()
    }

    #[test]
    fn test_platform_title_shells_are_strong() {
        for title in [
            "meet - david/pablo sync",
            "meet \u{2013} pablo / jorge",
            "meet \u{2013} pablo / jorge - fen\u{ea}tre de la pr\u{e9}sentation",
            "call re. vp eng role: pablo & paul | microsoft teams",
            "meeting join | microsoft teams meeting | microsoft teams",
            "join from zoom workplace app - zoom",
            "cisco webex meetings",
            "acme \u{2014} slack | huddle",
        ] {
            assert!(
                title_has_meeting_shell(title),
                "shell should match: {title}"
            );
            assert_eq!(
                meeting_context("google chrome", title, MEETINGS),
                Some(MeetingConfidence::Strong),
                "should be strong: {title}"
            );
        }
    }

    #[test]
    fn test_native_client_is_strong_and_bare_keyword_is_weak() {
        assert_eq!(
            meeting_context("zoom.us", "zoom", MEETINGS),
            Some(MeetingConfidence::Strong)
        );
        // A whole-word keyword and nothing else: any rename produces this, so it
        // keeps the lower tier and the tighter streak cap.
        assert_eq!(
            meeting_context(
                "google chrome",
                "gpt-5.6: meet sol, terra and luna",
                MEETINGS
            ),
            Some(MeetingConfidence::Weak)
        );
    }

    #[test]
    fn test_non_meeting_pages_still_match_nothing() {
        for title in [
            "recall.ai: the universal api for meeting bots | product hunt",
            "meeting notes - q3",
            "myzoomrecording.mp4",
            "meeting with michael - gmail",
        ] {
            assert_eq!(
                meeting_context("google chrome", title, MEETINGS),
                None,
                "should not match: {title}"
            );
        }
    }

    #[test]
    fn test_normalize_title_ignores_browser_decoration() {
        // Chrome appends a speaker glyph while a tab plays audio and prefixes an
        // unread count; neither means the meeting ended.
        assert_eq!(
            normalize_title("joe yetter <> pablo fernandez \u{1f50a}"),
            normalize_title("joe yetter <> pablo fernandez")
        );
        assert_eq!(
            normalize_title("(3) joe yetter <> pablo fernandez"),
            normalize_title("joe yetter <> pablo fernandez")
        );
    }

    #[test]
    fn test_zoom_web_client_call_stays_a_meeting() {
        // The observed sequence: the join page carries a Zoom marker, then the
        // web client retitles the tab to the meeting topic alone and nothing in
        // the window identifies a meeting again until the call ends.
        let out = drive(&[
            ("Google Chrome", "Join from Zoom Workplace app - Zoom", 30),
            ("Google Chrome", "Joe Yetter <> Pablo Fernandez", 4),
            ("Google Chrome", "Joe Yetter <> Pablo Fernandez", 0),
            (
                "Google Chrome",
                "Joe Yetter <> Pablo Fernandez \u{1f50a}",
                0,
            ),
            (
                "Google Chrome",
                "Joe Yetter <> Pablo Fernandez \u{1f50a}",
                0,
            ),
            ("Google Chrome", "Carol: Day grid reservation", 11),
            ("Google Chrome", "Carol: Day grid reservation", 0),
        ]);

        assert_eq!(out[0].0, ActivityClassification::Active);
        assert_eq!(out[1].0, ActivityClassification::Active);
        for i in 2..=4 {
            assert_eq!(
                out[i],
                (
                    ActivityClassification::Meeting,
                    Some(MeetingConfidence::Strong)
                ),
                "minute {i} of the call"
            );
        }
        // The call ends when the window becomes unrelated content.
        assert_eq!(out[5].0, ActivityClassification::Active);
        assert_eq!(out[6].0, ActivityClassification::Idle);
    }

    #[test]
    fn test_only_a_launcher_licenses_adopting_a_new_title() {
        // "Meet - Standup" identifies itself for the whole call, so it never
        // needs adoption — and must not hand its credit to the next tab.
        let out = drive(&[
            ("Google Chrome", "Meet - Standup", 0),
            ("Google Chrome", "reddit: the front page", 0),
        ]);
        assert_eq!(
            out[0],
            (
                ActivityClassification::Meeting,
                Some(MeetingConfidence::Strong)
            )
        );
        assert_eq!(out[1].0, ActivityClassification::Idle);
    }

    #[test]
    fn test_meeting_session_does_not_follow_an_app_switch() {
        let out = drive(&[
            ("Google Chrome", "Join from Zoom Workplace app - Zoom", 5),
            ("Google Chrome", "Joe <> Pablo", 0),
            ("Finder", "Joe <> Pablo", 0),
        ]);
        assert_eq!(out[1].0, ActivityClassification::Meeting);
        assert_eq!(out[2].0, ActivityClassification::Idle);
    }

    #[test]
    fn test_recent_activity_window_covers_a_reading_pause() {
        // One minute of input, then silence in a whitelisted app. Credit lasts
        // the rolling window rather than a single minute.
        let mut minutes = vec![("VSCode", "main.rs", 40u32)];
        minutes.extend(std::iter::repeat(("VSCode", "main.rs", 0u32)).take(12));
        let out = drive(&minutes);

        assert_eq!(out[0].0, ActivityClassification::Active);
        for i in 1..=RECENT_ACTIVITY_WINDOW_MINUTES as usize {
            assert_eq!(
                out[i].0,
                ActivityClassification::PassiveReview,
                "minute {i} should still be within the window"
            );
        }
        assert_eq!(
            out[RECENT_ACTIVITY_WINDOW_MINUTES as usize + 1].0,
            ActivityClassification::Idle,
            "credit ends once the window closes"
        );
    }

    #[test]
    fn test_input_during_a_call_reopens_the_window() {
        // A call the user types in stays Active, and the meeting session survives
        // the interruption because the window never changed.
        let out = drive(&[
            ("Google Chrome", "Join from Zoom Workplace app - Zoom", 5),
            ("Google Chrome", "Joe <> Pablo", 0),
            ("Google Chrome", "Joe <> Pablo", 22),
            ("Google Chrome", "Joe <> Pablo", 0),
        ]);
        assert_eq!(out[1].0, ActivityClassification::Meeting);
        assert_eq!(out[2].0, ActivityClassification::Active);
        assert_eq!(
            out[3],
            (
                ActivityClassification::Meeting,
                Some(MeetingConfidence::Strong)
            )
        );
    }
}
