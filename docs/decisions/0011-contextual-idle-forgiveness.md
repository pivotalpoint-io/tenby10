# ADR 0011: Contextual Idle Forgiveness via Delayed Aggregation

## Status
Accepted

## Context
Tenby10 evaluates user productivity in 10-minute slots. A strict real-time evaluation penalizes users for taking short pauses (e.g., reading a PR, conceptualizing an architecture, thinking through a bug) if those pauses occur at the boundary of a 10-minute slot (e.g., minutes 8 and 9 of the slot). This creates an inaccurate and unfairly low "Focus Score" for sessions that are otherwise highly productive. We need a way to mathematically differentiate between a genuine distraction (leaving the desk for 20 minutes) and "Thinking Time" (pausing for 3 minutes before resuming work).

## Decision
We have decided to implement a **5-Minute Delayed Contextual Aggregator**.

1. **Immutable Raw Telemetry**: The daemon will continue to record hardware inputs accurately per minute. If there are 0 keystrokes and 0 clicks, the raw minute log will reflect 0 inputs. We will never retroactively falsify raw telemetry.
2. **Delayed Compilation**: The 10-minute slot aggregator will wait exactly 5 minutes after a slot ends before evaluating it (e.g., a 09:00 - 09:10 slot is evaluated at 09:15).
3. **Contextual Reconciliation**: During evaluation, the aggregator fetches the raw logs from the first 5 minutes of the *next* slot (the "future context"). 
4. **Forgiveness Threshold**: The aggregator measures the length of consecutive idle minutes at the absolute end of the current slot, plus the consecutive idle minutes at the beginning of the future slot. 
   - If the total contiguous pause is **<= 5 minutes**, and the user successfully resumed working within the 5-minute future window, the pause is classified as a "Continuous Reading/Thinking Session".
   - The trailing idle minutes in the current slot are mathematically forgiven, re-categorized as `Productive`, and added to the Focus Score numerator.
   - If the total pause exceeds 5 minutes, it is classified as a genuine absence/distraction and no forgiveness is granted.

## Consequences
- **Positive**: Massively improves the accuracy of Focus Scores. Eliminates the frustration of being penalized for pausing to read a document near a slot boundary. Maintains the integrity of raw telemetry data.
- **Negative**: Introduces a deliberate 5-minute delay in the dashboard for real-time slot visualization. A slot ending at 09:10 will show as "Evaluating..." until 09:15. This is deemed a highly acceptable trade-off for data accuracy.
