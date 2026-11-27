use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

use super::{
    AttestationsPane, Focus, Item,
    chart::{self, committee_color, dim, exact, fg, secs},
    panel::{Panel, Row, rule},
};
use crate::sources::pq::TimeBase;

pub const WIDTH: u16 = 42;

pub fn draw(f: &mut Frame, area: Rect, pane: &mut AttestationsPane) {
    let info = pane.data().slot(pane.slot);
    let all = chart::vote_times(pane, None);
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let mut fixed: Vec<Row> = Vec::new();
    let filter = pane
        .committee_filter
        .map_or_else(|| "all committees".into(), |committee| format!("committee {committee}"));
    fixed.push(rule(&filter, area.width));
    fixed.push((
        Line::styled(
            format!("  {:<9}{:<10}{:<9} {}", "received", "committee", "validator", "in proof"),
            bold,
        ),
        None,
    ));

    let mut list: Vec<Row> = Vec::new();
    for &index in &info.votes {
        let vote = &pane.data().votes[index];
        if !pane.seen(vote.received) ||
            pane.committee_filter.is_some_and(|committee| vote.committee != committee)
        {
            continue;
        }
        let proof = (vote.proved_by.or(vote.block_job))
            .and_then(|job| pane.data().jobs.get(job))
            .filter(|job| pane.seen(job.answered))
            .map_or_else(|| Span::styled("—", dim()), |job| Span::raw(format!("#{}", job.id)));
        let line = Line::from(vec![
            Span::raw(format!("  {:<9}", exact(pane.rel(vote.received)))),
            Span::styled(
                format!("{:<10}", format!("c{}", vote.committee)),
                fg(committee_color(vote.committee)),
            ),
            Span::raw(format!("{:<9} ", vote.validator)),
            proof,
        ]);
        list.push((line, Some(Item::Vote(index))));
    }

    let panel = Panel {
        title: "votes received",
        summary: format!("{} of {}", all.len(), info.members()),
        fixed,
        list,
    };
    panel.draw(f, area, pane.focus == Focus::Votes, &mut pane.votes);
}

/// Seen, median, p90, and how many came after attestation due.
pub fn spread(label: &str, times: &[f64], size: usize, time: &TimeBase) -> Vec<Span<'static>> {
    let at =
        |q: f64| times.get(((times.len().saturating_sub(1)) as f64 * q).round() as usize).copied();
    let timed = |ms: Option<f64>| match ms {
        None => Span::styled(format!("{:>8}", "·"), dim()),
        Some(ms) => {
            let color = match ms {
                ms if ms < time.attestation_due_ms => Color::Green,
                ms if ms < time.aggregate_due_ms => Color::Yellow,
                _ => Color::Red,
            };
            Span::styled(format!("{:>8}", secs(ms)), fg(color))
        }
    };
    let late = times.iter().filter(|&&ms| ms > time.attestation_due_ms).count();
    vec![
        Span::raw(format!("{label:<10}")),
        Span::raw(format!("{:>11}", format!("{}/{size}", times.len()))),
        timed(at(0.5)),
        timed(at(0.9)),
        Span::styled(format!("{late:>6}"), if late > 0 { fg(Color::Yellow) } else { dim() }),
    ]
}
