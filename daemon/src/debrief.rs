//! The private daily debrief (#113).
//!
//! A debrief is the worker-facing counterpart of the client-facing work note: one
//! candid paragraph about the day plus a deterministic account of where the time
//! went. It exists for the person who did the work and for nobody else, which is
//! why everything about it is built to stay on the machine: it is stored in its
//! own table with no hash, no signature and no sync flag (`db::insert_daily_debrief`),
//! the sync module never reads that table, and rows expire after
//! [`crate::daemon::DEBRIEF_RETENTION_DAYS`] unless the worker keeps them.
//!
//! **Explanation scales with the gap.** The debrief explains variance, not virtue.
//! Every day gets one neutral accounting line (numbers, no names). Only when
//! credited time falls well short of presence ([`needs_reconciliation`]) do the
//! distraction and idle episodes reach the model at all — on an ordinary day they
//! are withheld from the prompt entirely, so the narrative cannot moralize about a
//! day that needs no explaining, and the junk-site titles those episodes tend to
//! carry stay out of the request.
//!
//! This module is pure bookkeeping: segmentation, accounting, and prompt lines.
//! Generation (the AI call, storage, retention) lives in
//! `daemon::generate_pending_debriefs`.

use crate::db::MinuteLogData;
use std::collections::HashMap;

/// Reconciliation triggers when credited time is under this share of presence…
pub const RECON_MAX_CREDITED_PCT: u32 = 70;
/// …and the absolute gap also exceeds this many minutes. The pair means short
/// days are not punished (3h credited of 3.5h present stays quiet) and long good
/// days are not lectured (10h of 12h stays quiet).
pub const RECON_MIN_GAP_MINUTES: u32 = 60;

/// Episodes shorter than this are folded into a neighbour: a one-minute detour
/// is texture, not an episode. Deliberate cost: a stretch of rapid app-flipping
/// collapses into the episode it interrupts rather than rendering as confetti.
pub const SHORT_EPISODE_MIN_MINUTES: u32 = 2;

/// A hole between logged minutes at least this long becomes an explicit "Away"
/// episode. Locked or asleep minutes are never logged, so the gaps are real and
/// naming them is what lets the narrative describe the shape of the day
/// ("long break around lunch") instead of leaving unexplained holes.
pub const AWAY_GAP_MIN_SECS: i64 = 120;

/// Ceiling on episode lines handed to the model. On a pathologically fragmented
/// day the longest episodes are kept and re-sorted chronologically, so the cap
/// trims resolution, never the day's shape.
pub const DIGEST_MAX_LINES: usize = 80;

/// One contiguous stretch of the day: same app, same state, no gap.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Episode {
    pub start: i64,
    /// Exclusive end (last minute's timestamp + 60).
    pub end: i64,
    pub minutes: u32,
    pub app: String,
    /// The title seen for the most minutes of the episode.
    pub title: String,
    /// "Active" | "PassiveReview" | "Meeting" | "Idle" | "Distracted" |
    /// "Tampered" | "Away".
    pub state: String,
    pub keys: u32,
    pub clicks: u32,
    pub scrolls: u32,
    /// For a Distracted episode: the configured `distracting_apps` keyword that
    /// matched. Stored so the dashboard's "not a distraction" control can name
    /// exactly what it would remove.
    pub matched_keyword: Option<String>,
}

/// The day's arithmetic, summed from the slots' own signed category counts —
/// the same numbers the ledger carries, not a re-derivation that could drift.
#[derive(Debug, Clone, Copy, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct DayAccounting {
    pub presence: u32,
    pub credited: u32,
    pub meeting: u32,
    pub waste: u32,
    pub idle: u32,
    pub tampered: u32,
}

impl DayAccounting {
    /// Build from a summed `app_categories` map ("Productive"/"Meeting"/"Waste"/
    /// "Inactive"/"Tampered" → minutes).
    pub fn from_category_minutes(categories: &HashMap<String, u32>) -> Self {
        let get = |k: &str| categories.get(k).copied().unwrap_or(0);
        let productive = get("Productive");
        let meeting = get("Meeting");
        let waste = get("Waste");
        let idle = get("Inactive");
        let tampered = get("Tampered");
        DayAccounting {
            presence: productive + meeting + waste + idle + tampered,
            credited: productive + meeting,
            meeting,
            waste,
            idle,
            tampered,
        }
    }
}

/// Whether the day's gap is material enough to explain: credited under
/// [`RECON_MAX_CREDITED_PCT`] of presence AND more than [`RECON_MIN_GAP_MINUTES`]
/// unaccounted for. Both constants live in code, not config — a threshold the
/// worker could tune would quietly become a verdict they set for themselves.
pub fn needs_reconciliation(acc: &DayAccounting) -> bool {
    acc.presence > 0
        && acc.credited * 100 < acc.presence * RECON_MAX_CREDITED_PCT
        && acc.presence - acc.credited > RECON_MIN_GAP_MINUTES
}

/// "7h50m" / "45m" / "0m".
pub fn format_duration_minutes(minutes: u32) -> String {
    if minutes >= 60 {
        let m = minutes % 60;
        if m == 0 {
            format!("{}h", minutes / 60)
        } else {
            format!("{}h{:02}m", minutes / 60, m)
        }
    } else {
        format!("{}m", minutes)
    }
}

/// The always-shown accounting line: numbers, no names, no judgment.
/// "9h12m at the computer · 7h50m credited (1h40m in meetings) · 1h22m other"
pub fn format_accounting_line(acc: &DayAccounting) -> String {
    let mut line = format!(
        "{} at the computer · {} credited",
        format_duration_minutes(acc.presence),
        format_duration_minutes(acc.credited),
    );
    if acc.meeting > 0 {
        line.push_str(&format!(
            " ({} in meetings)",
            format_duration_minutes(acc.meeting)
        ));
    }
    let other = acc.presence.saturating_sub(acc.credited);
    if other > 0 {
        line.push_str(&format!(" · {} other", format_duration_minutes(other)));
    }
    line
}

/// Local wall-clock HH:MM for a timestamp, falling back to the raw number when
/// the local time is unrepresentable (a DST edge).
pub fn hh_mm(ts: i64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format("%H:%M").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Which configured distraction keyword a minute matched, if any. Mirrors the
/// evaluator's matching (case-insensitive substring over app and title) so the
/// stored keyword is the one that actually caused the classification.
fn matched_distraction_keyword(app: &str, title: &str, distracting_apps: &str) -> Option<String> {
    let app_lower = app.to_lowercase();
    let title_lower = title.to_lowercase();
    distracting_apps
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .find(|kw| app_lower.contains(kw) || title_lower.contains(kw))
}

/// Segment a day of minute logs into [`Episode`]s.
///
/// `states[i]` is the evaluator's verdict for `logs[i]` — computed by the caller
/// with the same rules the slots were scored under, minus billing-only
/// adjustments (the silent-meeting demotion exists to bound credit, not to
/// describe a day). Boundaries fall on an app change, a state change, or a gap
/// of [`AWAY_GAP_MIN_SECS`]+ (which becomes an explicit Away episode). Episodes
/// shorter than [`SHORT_EPISODE_MIN_MINUTES`] are folded into their neighbour.
pub fn build_episodes(
    logs: &[MinuteLogData],
    states: &[&'static str],
    distracting_apps: &str,
) -> Vec<Episode> {
    assert_eq!(logs.len(), states.len(), "one state per minute");

    struct Open {
        start: i64,
        end: i64,
        app: String,
        state: &'static str,
        keys: u32,
        clicks: u32,
        scrolls: u32,
        title_minutes: HashMap<String, u32>,
        matched_keyword: Option<String>,
    }

    fn close(open: Open) -> Episode {
        let title = open
            .title_minutes
            .iter()
            .max_by_key(|(_, m)| **m)
            .map(|(t, _)| t.clone())
            .unwrap_or_default();
        Episode {
            start: open.start,
            end: open.end,
            minutes: ((open.end - open.start) / 60).max(0) as u32,
            app: open.app,
            title,
            state: open.state.to_string(),
            keys: open.keys,
            clicks: open.clicks,
            scrolls: open.scrolls,
            matched_keyword: open.matched_keyword,
        }
    }

    let mut episodes: Vec<Episode> = Vec::new();
    let mut open: Option<Open> = None;

    for (log, state) in logs.iter().zip(states.iter()) {
        if let Some(cur) = &open {
            let gap = log.timestamp - cur.end;
            if gap >= AWAY_GAP_MIN_SECS {
                let (away_start, away_end) = (cur.end, log.timestamp);
                episodes.push(close(open.take().unwrap()));
                episodes.push(Episode {
                    start: away_start,
                    end: away_end,
                    minutes: ((away_end - away_start) / 60).max(0) as u32,
                    app: String::new(),
                    title: String::new(),
                    state: "Away".to_string(),
                    keys: 0,
                    clicks: 0,
                    scrolls: 0,
                    matched_keyword: None,
                });
            } else if cur.app != log.active_app_name || cur.state != *state {
                episodes.push(close(open.take().unwrap()));
            }
        }

        match open.as_mut() {
            Some(cur) => {
                cur.end = log.timestamp + 60;
                cur.keys += log.keystroke_count;
                cur.clicks += log.mouse_click_count;
                cur.scrolls += log.scroll_event_count;
                *cur.title_minutes
                    .entry(log.active_window_title.clone())
                    .or_insert(0) += 1;
            }
            None => {
                let matched = if *state == "Distracted" {
                    matched_distraction_keyword(
                        &log.active_app_name,
                        &log.active_window_title,
                        distracting_apps,
                    )
                } else {
                    None
                };
                let mut title_minutes = HashMap::new();
                title_minutes.insert(log.active_window_title.clone(), 1);
                open = Some(Open {
                    start: log.timestamp,
                    end: log.timestamp + 60,
                    app: log.active_app_name.clone(),
                    state,
                    keys: log.keystroke_count,
                    clicks: log.mouse_click_count,
                    scrolls: log.scroll_event_count,
                    title_minutes,
                    matched_keyword: matched,
                });
            }
        }
    }
    if let Some(cur) = open {
        episodes.push(close(cur));
    }

    // Fold sub-threshold episodes into the previous mergeable neighbour; a short
    // head episode folds forward into the one after it instead. Away episodes
    // neither absorb nor get absorbed — a real hole in the day stays a hole.
    let mut merged: Vec<Episode> = Vec::new();
    for ep in episodes {
        let short = ep.minutes < SHORT_EPISODE_MIN_MINUTES && ep.state != "Away";
        match merged.last_mut() {
            Some(prev) if short && prev.state != "Away" => {
                prev.end = ep.end;
                prev.minutes += ep.minutes;
                prev.keys += ep.keys;
                prev.clicks += ep.clicks;
                prev.scrolls += ep.scrolls;
            }
            _ => merged.push(ep),
        }
    }
    if merged.len() >= 2
        && merged[0].minutes < SHORT_EPISODE_MIN_MINUTES
        && merged[0].state != "Away"
        && merged[1].state != "Away"
    {
        let head = merged.remove(0);
        let next = &mut merged[0];
        next.start = head.start;
        next.minutes += head.minutes;
        next.keys += head.keys;
        next.clicks += head.clicks;
        next.scrolls += head.scrolls;
    }
    merged
}

/// The episode lines handed to the model, chronological, scrubbed, capped.
///
/// `include_offwork` is the reconciliation switch: `false` (a quiet day) keeps
/// only Active / PassiveReview / Meeting / Away episodes, so distraction and
/// idle detail — and the titles it carries — never reaches the model at all;
/// `true` (a day whose gap needs explaining) includes everything. Away lines
/// survive both modes: they carry no title and they are the shape of the day.
pub fn digest_lines(episodes: &[Episode], include_offwork: bool) -> Vec<String> {
    let mut kept: Vec<&Episode> = episodes
        .iter()
        .filter(|ep| {
            include_offwork
                || matches!(
                    ep.state.as_str(),
                    "Active" | "PassiveReview" | "Meeting" | "Away"
                )
        })
        .collect();

    if kept.len() > DIGEST_MAX_LINES {
        kept.sort_by_key(|ep| std::cmp::Reverse(ep.minutes));
        kept.truncate(DIGEST_MAX_LINES);
        kept.sort_by_key(|ep| ep.start);
    }

    kept.iter()
        .map(|ep| {
            if ep.state == "Away" {
                format!(
                    "{}–{} ({}) — Away from the computer (no minutes recorded)",
                    hh_mm(ep.start),
                    hh_mm(ep.end),
                    format_duration_minutes(ep.minutes),
                )
            } else {
                format!(
                    "{}–{} ({}) — App: '{}', Title: '{}', State: {}, Keys: {}, Clicks: {}, Scrolls: {}",
                    hh_mm(ep.start),
                    hh_mm(ep.end),
                    format_duration_minutes(ep.minutes),
                    crate::untrusted::scrub(&ep.app),
                    crate::untrusted::scrub(&ep.title),
                    ep.state,
                    ep.keys,
                    ep.clicks,
                    ep.scrolls,
                )
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minute(ts: i64, app: &str, title: &str, keys: u32) -> MinuteLogData {
        MinuteLogData {
            timestamp: ts,
            keystroke_count: keys,
            mouse_click_count: 0,
            scroll_event_count: 0,
            active_app_name: app.to_string(),
            active_window_title: title.to_string(),
            low_entropy: false,
            mouse_movement_distance: 0.0,
        }
    }

    #[test]
    fn episodes_split_on_app_and_state_and_absorb_one_minute_blips() {
        // 4m coding, a 1m chat blip (absorbed), 3m more coding, then 3m YouTube.
        let logs = vec![
            minute(0, "Code", "billing.rs", 50),
            minute(60, "Code", "billing.rs", 40),
            minute(120, "Code", "sync.rs", 45),
            minute(180, "Code", "billing.rs", 30),
            minute(240, "Slack", "#general", 5),
            minute(300, "Code", "billing.rs", 60),
            minute(360, "Code", "billing.rs", 55),
            minute(420, "Code", "billing.rs", 20),
            minute(480, "YouTube", "cat videos", 0),
            minute(540, "YouTube", "cat videos", 3),
            minute(600, "YouTube", "cat videos", 0),
        ];
        let states: Vec<&'static str> = vec![
            "Active",
            "Active",
            "Active",
            "Active",
            "Active",
            "Active",
            "Active",
            "Active",
            "Distracted",
            "Distracted",
            "Distracted",
        ];
        let eps = build_episodes(&logs, &states, "youtube");
        assert_eq!(eps.len(), 3, "code, code-again, youtube: {eps:#?}");
        assert_eq!(eps[0].app, "Code");
        assert_eq!(eps[0].minutes, 5, "the 1m Slack blip is folded in");
        assert_eq!(eps[0].title, "billing.rs", "dominant title wins");
        assert_eq!(eps[1].app, "Code");
        assert_eq!(eps[2].state, "Distracted");
        assert_eq!(eps[2].matched_keyword.as_deref(), Some("youtube"));
        assert_eq!(eps[2].minutes, 3);
    }

    #[test]
    fn a_gap_becomes_an_away_episode_and_short_head_folds_forward() {
        let logs = vec![
            minute(0, "Code", "a.rs", 10),
            // 58 minutes of nothing recorded.
            minute(3540, "Code", "a.rs", 10),
            minute(3600, "Code", "a.rs", 10),
        ];
        let states: Vec<&'static str> = vec!["Active", "Active", "Active"];
        let eps = build_episodes(&logs, &states, "");
        assert_eq!(eps.len(), 3, "{eps:#?}");
        assert_eq!(eps[1].state, "Away");
        assert_eq!(eps[1].minutes, 58);
        // The 1-minute head could not merge backwards (nothing there) and must
        // not merge across the Away hole.
        assert_eq!(eps[0].minutes, 1);
        assert_eq!(eps[2].minutes, 2);
    }

    #[test]
    fn reconciliation_trigger_matches_the_worked_examples() {
        let acc = |presence, credited, meeting| DayAccounting {
            presence,
            credited,
            meeting,
            waste: 0,
            idle: presence - credited,
            tampered: 0,
        };
        // 10h credited of 12h present: quiet (83% yield).
        assert!(!needs_reconciliation(&acc(720, 600, 0)));
        // 3h credited of 8h present: explain (37%, 5h gap).
        assert!(needs_reconciliation(&acc(480, 180, 0)));
        // Short good day, 3h of 3.5h: quiet (86%).
        assert!(!needs_reconciliation(&acc(210, 180, 0)));
        // 11h of 12h with 5h meetings: meetings are credited, quiet.
        assert!(!needs_reconciliation(&acc(720, 660, 300)));
        // Low ratio but the absolute gap stays under the hour floor
        // (45m credited of 100m present, 55m gap): quiet.
        assert!(!needs_reconciliation(&acc(100, 45, 0)));
        // Empty day: quiet.
        assert!(!needs_reconciliation(&DayAccounting::default()));
    }

    #[test]
    fn accounting_line_reads_as_numbers_without_judgment() {
        let acc = DayAccounting {
            presence: 552,
            credited: 470,
            meeting: 100,
            waste: 42,
            idle: 40,
            tampered: 0,
        };
        assert_eq!(
            format_accounting_line(&acc),
            "9h12m at the computer · 7h50m credited (1h40m in meetings) · 1h22m other"
        );
        let clean = DayAccounting {
            presence: 60,
            credited: 60,
            meeting: 0,
            waste: 0,
            idle: 0,
            tampered: 0,
        };
        assert_eq!(
            format_accounting_line(&clean),
            "1h at the computer · 1h credited"
        );
    }

    #[test]
    fn quiet_days_withhold_offwork_episodes_from_the_model() {
        let eps = vec![
            Episode {
                start: 0,
                end: 600,
                minutes: 10,
                app: "Code".into(),
                title: "a.rs".into(),
                state: "Active".into(),
                keys: 100,
                clicks: 5,
                scrolls: 0,
                matched_keyword: None,
            },
            Episode {
                start: 600,
                end: 1800,
                minutes: 20,
                app: "YouTube".into(),
                title: "definitely not work".into(),
                state: "Distracted".into(),
                keys: 0,
                clicks: 9,
                scrolls: 40,
                matched_keyword: Some("youtube".into()),
            },
            Episode {
                start: 1800,
                end: 2400,
                minutes: 10,
                app: String::new(),
                title: String::new(),
                state: "Away".into(),
                keys: 0,
                clicks: 0,
                scrolls: 0,
                matched_keyword: None,
            },
        ];
        let quiet = digest_lines(&eps, false);
        assert_eq!(quiet.len(), 2, "work + away survive: {quiet:#?}");
        assert!(
            quiet.iter().all(|l| !l.contains("definitely not work")),
            "a distraction title must not reach a quiet day's prompt"
        );
        let recon = digest_lines(&eps, true);
        assert_eq!(recon.len(), 3);
        assert!(recon[1].contains("State: Distracted"));
    }

    #[test]
    fn digest_cap_keeps_longest_but_renders_chronologically() {
        let mut eps = Vec::new();
        for i in 0..(DIGEST_MAX_LINES as i64 + 20) {
            eps.push(Episode {
                start: i * 600,
                end: i * 600 + 600,
                minutes: if i % 2 == 0 { 10 } else { 2 },
                app: format!("App{i}"),
                title: "t".into(),
                state: "Active".into(),
                keys: 1,
                clicks: 0,
                scrolls: 0,
                matched_keyword: None,
            });
        }
        let lines = digest_lines(&eps, true);
        assert_eq!(lines.len(), DIGEST_MAX_LINES);
        // Chronology is checked via the unique app index in each line, not the
        // HH:MM label — wall-clock order isn't lexical across midnight.
        let indices: Vec<usize> = lines
            .iter()
            .map(|l| {
                l.split("App: 'App")
                    .nth(1)
                    .and_then(|rest| rest.split('\'').next())
                    .and_then(|n| n.parse().ok())
                    .expect("every kept line carries its app index")
            })
            .collect();
        assert!(
            indices.windows(2).all(|w| w[0] < w[1]),
            "chronological after the cap: {indices:?}"
        );
    }
}
