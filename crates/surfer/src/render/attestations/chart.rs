use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};

use super::{
    AttestationsPane,
    strip::{Axis, Guide, Strip},
};
use crate::sources::pq::{TargetKey, TimeBase};

/// Cycles past eight committees; the PQ mainnet preset allows sixteen.
pub const COMMITTEE_COLOURS: u8 = 8;
const COMMITTEE_COLORS: [Color; COMMITTEE_COLOURS as usize] = [
    Color::Rgb(230, 125, 25),
    Color::Rgb(90, 140, 240),
    Color::Rgb(175, 120, 235),
    Color::Rgb(80, 200, 120),
    Color::Rgb(235, 200, 60),
    Color::Rgb(240, 110, 160),
    Color::Rgb(90, 210, 230),
    Color::Rgb(190, 190, 190),
];
pub const JOB_COLOR: Color = Color::Rgb(20, 150, 130);
pub const BLOCK_JOB_COLOR: Color = Color::Rgb(60, 120, 200);
pub const PROVING_COLOR: Color = Color::Rgb(90, 200, 180);
pub const FAILED_COLOR: Color = Color::Rgb(200, 50, 50);
/// The merge failed: no answer, a leanVM refusal, or a rejected answer.
pub const REJECTED_COLOR: Color = Color::Rgb(170, 70, 190);
pub const HISTOGRAM_ROWS: usize = 6;
const BIN_SIZES_MS: [f64; 9] = [10.0, 20.0, 25.0, 50.0, 100.0, 200.0, 250.0, 500.0, 1_000.0];
const BARS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

pub fn secs(ms: f64) -> String {
    format!("{:.2}s", ms / 1_000.0)
}

pub fn exact(ms: f64) -> String {
    format!("{:.3}s", ms / 1_000.0)
}

pub fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn fg(color: Color) -> Style {
    Style::default().fg(color)
}

pub fn committee_color(committee: u8) -> Color {
    COMMITTEE_COLORS[usize::from(committee) % COMMITTEE_COLORS.len()]
}

pub fn target_name(key: TargetKey) -> String {
    match key {
        TargetKey::Aggregate { committee, position } => {
            format!("committee {committee}·p{position}")
        }
        TargetKey::Block { block_slot } => format!("block {block_slot}"),
    }
}

/// Later guides win a shared column.
pub fn guides(pane: &AttestationsPane) -> Vec<Guide> {
    let time = &pane.data().time;
    let gray = fg(Color::Gray);
    let mut guides = vec![
        Guide { ms: time.slot_ms, ch: '┊', style: dim(), label: Some("next slot".into()) },
        Guide {
            ms: time.attestation_due_ms,
            ch: '┊',
            style: gray,
            label: Some("attestation due".into()),
        },
    ];
    // Each aggregator position is due one delay later; `group_labels` names them.
    for position in 0..time.aggregators() {
        let ms = time.aggregate_due_ms + f64::from(position) * time.aggregator_delay_ms;
        guides.push(Guide { ms, ch: '┊', style: gray, label: Some(format!("p{position}")) });
    }
    let now = pane.rel(pane.now);
    if now < 2.0 * time.slot_ms {
        guides
            .push(Guide { ms: now, ch: '│', style: fg(Color::Green), label: Some("now".into()) });
    }
    guides
}

pub fn labels(axis: &Axis, guides: &[Guide]) -> Strip {
    let mut strip = Strip::new(axis.width);
    for guide in guides {
        let (Some(col), Some(label)) = (axis.col(guide.ms), &guide.label) else { continue };
        // The trailing space keeps neighbouring labels apart.
        let label = format!("{label} ");
        if !strip.text(col, &label, guide.style) {
            strip.text(col.saturating_sub(label.chars().count() - 2), &label, guide.style);
        }
    }
    strip
}

/// Names the p0–p3 group of due lines, one row above their labels.
pub fn group_labels(axis: &Axis, time: &TimeBase) -> Strip {
    let mut strip = Strip::new(axis.width);
    if let Some(col) = axis.col(time.aggregate_due_ms) {
        let name = "aggregation due, by aggregator position";
        if !strip.text(col, name, fg(Color::Gray)) {
            strip.text(col, "aggregation due", fg(Color::Gray));
        }
    }
    strip
}

/// Vote arrival times into the slot, as seen by now.
pub fn vote_times(pane: &AttestationsPane, committee: Option<u8>) -> Vec<f64> {
    let mut times: Vec<f64> = (pane.data().slot(pane.slot).votes.iter())
        .map(|&index| &pane.data().votes[index])
        .filter(|vote| pane.seen(vote.received))
        .filter(|vote| committee.is_none_or(|committee| vote.committee == committee))
        .map(|vote| pane.rel(vote.received))
        .collect();
    times.sort_by(f64::total_cmp);
    times
}

/// The finest round size that still gives every bin at least one column.
pub fn bin_ms(axis: &Axis) -> f64 {
    BIN_SIZES_MS
        .into_iter()
        .find(|&size| size >= axis.ms_per_col())
        .unwrap_or(BIN_SIZES_MS[BIN_SIZES_MS.len() - 1])
}

/// Stacked by committee, committee 0 at the bottom. Each column shows the
/// bin under its centre, so a bin wider than a column spans several columns.
/// A cell takes the colour of the committee at its middle height.
pub fn histogram(pane: &AttestationsPane, axis: &Axis) -> Vec<Strip> {
    let bin = bin_ms(axis);
    let committees = pane.data().slot(pane.slot).committees.len();
    let mut bins = vec![vec![0usize; committees]; (axis.to / bin).ceil() as usize + 1];
    for committee in 0..committees as u8 {
        if pane.committee_filter.is_some_and(|only| only != committee) {
            continue;
        }
        for ms in vote_times(pane, Some(committee)) {
            if let Some(counts) = bins.get_mut((ms / bin) as usize) {
                counts[usize::from(committee)] += 1;
            }
        }
    }
    let empty = vec![0; committees];
    let columns: Vec<&Vec<usize>> = (0..axis.width)
        .map(|col| {
            let centre = axis.from + col as f64 * axis.ms_per_col();
            bins.get((centre / bin) as usize).unwrap_or(&empty)
        })
        .collect();
    let max =
        columns.iter().map(|counts| counts.iter().sum::<usize>()).max().unwrap_or(0).max(1) as f64;
    let eighths = (HISTOGRAM_ROWS * 8) as f64;
    (0..HISTOGRAM_ROWS)
        .map(|row| {
            let floor = ((HISTOGRAM_ROWS - 1 - row) * 8) as f64;
            let mut strip = Strip::new(axis.width);
            for (col, counts) in columns.iter().enumerate() {
                let total = counts.iter().sum::<usize>() as f64 * eighths / max;
                let fill = (total.ceil() - floor).clamp(0.0, 8.0);
                if fill == 0.0 {
                    continue;
                }
                // Rounding the bar up can lift the middle of its top cell
                // above the stack; that cell belongs to the top committee.
                let level = (floor + fill / 2.0).min(total);
                let mut stacked = 0.0;
                let top = counts.iter().rposition(|&count| count > 0).unwrap_or(0);
                let committee = counts
                    .iter()
                    .position(|&count| {
                        stacked += count as f64 * eighths / max;
                        count > 0 && level <= stacked
                    })
                    .unwrap_or(top);
                strip.set(col, BARS[fill as usize], fg(committee_color(committee as u8)));
            }
            strip
        })
        .collect()
}

/// `◆` received, `◈` several in one column, `◇` our own.
pub fn aggregate_dots(pane: &AttestationsPane, axis: &Axis) -> Strip {
    let mut strip = Strip::new(axis.width);
    for &index in pane.data().aggregates_of(pane.slot) {
        let aggregate = &pane.data().aggregates[index];
        if !pane.seen(aggregate.received) ||
            pane.committee_filter.is_some_and(|only| only != aggregate.committee)
        {
            continue;
        }
        let Some(col) = axis.col(pane.rel(aggregate.received)) else { continue };
        let ch = match aggregate.local {
            true => '◇',
            false if matches!(strip.get(col), Some('◆' | '◈')) => '◈',
            false => '◆',
        };
        strip.set(col, ch, fg(committee_color(aggregate.committee)).add_modifier(Modifier::BOLD));
    }
    strip
}

pub fn ticks(axis: &Axis) -> Strip {
    let mut strip = Strip::new(axis.width);
    let step = axis.tick_step();
    let mut ms = (axis.from / step).ceil() * step;
    while ms < axis.to {
        if let Some(col) = axis.col(ms) {
            strip.text(col, &format!("{} s", ms / 1_000.0), dim());
        }
        ms += step;
    }
    strip
}

pub fn swatch(color: Color, text: &str) -> [Span<'static>; 2] {
    [Span::styled("■ ", fg(color)), Span::raw(format!("{text}   "))]
}
