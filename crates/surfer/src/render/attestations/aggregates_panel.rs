use std::collections::BTreeSet;

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

use super::{
    AttestationsPane, Focus, Item,
    chart::{committee_color, dim, exact, fg},
    panel::{Panel, Row, rule},
};
use crate::sources::pq::Aggregate;

pub const WIDTH: u16 = 65;

pub fn draw(f: &mut Frame, area: Rect, pane: &mut AttestationsPane) {
    let mut shown: Vec<usize> = (pane.data().aggregates_of(pane.slot).iter().copied())
        .filter(|&index| pane.seen(pane.data().aggregates[index].received))
        .filter(|&index| {
            pane.committee_filter.is_none_or(|only| only == pane.data().aggregates[index].committee)
        })
        .collect();
    // Ours are appended when published, after the received ones.
    shown.sort_by(|&a, &b| {
        pane.data().aggregates[a].received.total_cmp(&pane.data().aggregates[b].received)
    });
    let aggregates: Vec<&Aggregate> =
        shown.iter().map(|&index| &pane.data().aggregates[index]).collect();
    let committees: BTreeSet<u8> = aggregates.iter().map(|aggregate| aggregate.committee).collect();
    let ours = aggregates.iter().filter(|aggregate| aggregate.local).count();
    let filter = pane
        .committee_filter
        .map_or_else(|| "all committees".into(), |committee| format!("committee {committee}"));
    let fixed = vec![
        rule(&filter, area.width),
        (
            Line::styled(
                format!(
                    "  {:<9}{:<11}{:<10}{:>10}{:>10}  {}",
                    "received", "aggregator", "validator", "after due", "attesters", "in proof"
                ),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            None,
        ),
    ];
    let list: Vec<Row> = shown.iter().map(|&index| row(pane, index)).collect();
    let mut summary = format!("{} over {} committees", aggregates.len(), committees.len());
    if ours > 0 {
        summary.push_str(&format!(" · {ours} ours"));
    }
    let panel = Panel { title: "aggregates", summary, fixed, list };
    panel.draw(f, area, pane.focus == Focus::Aggregates, &mut pane.aggregates);
}

/// Attesters of the committee's largest aggregate seen. Events carry counts,
/// not bits, so this is the floor of what all its aggregates cover.
pub fn best(pane: &AttestationsPane, committee: u8) -> usize {
    (pane.data().aggregates_of(pane.slot).iter())
        .map(|&index| &pane.data().aggregates[index])
        .filter(|aggregate| aggregate.committee == committee && pane.seen(aggregate.received))
        .map(|aggregate| usize::from(aggregate.attesters))
        .max()
        .unwrap_or(0)
}

fn row(pane: &AttestationsPane, index: usize) -> Row {
    let aggregate = &pane.data().aggregates[index];
    let after_due =
        aggregate.received - pane.data().time.aggregate_due(aggregate.slot, aggregate.position);
    let used = match aggregate.used_in {
        Some((job, _)) if pane.seen(pane.data().jobs[job].answered) => {
            Span::raw(format!("#{}", pane.data().jobs[job].id))
        }
        _ => Span::styled("—", dim()),
    };
    let from = if aggregate.local { "ours".to_string() } else { aggregate.aggregator.to_string() };
    let line = Line::from(vec![
        Span::raw(format!("  {:<9}", exact(pane.rel(aggregate.received)))),
        Span::styled(
            format!("c{:<3}", aggregate.committee),
            fg(committee_color(aggregate.committee)),
        ),
        Span::raw(format!("p{:<6}", aggregate.position)),
        Span::raw(format!("{from:<10}")),
        Span::styled(
            format!("{:>10}", format!("{after_due:+.0}ms")),
            if after_due > 1_000.0 { fg(Color::Red) } else { dim() },
        ),
        Span::raw(format!(
            "{:>10}",
            format!("{}/{}", aggregate.attesters, aggregate.committee_len)
        )),
        Span::raw("  "),
        used,
    ]);
    (line, Some(Item::Aggregate(index)))
}
