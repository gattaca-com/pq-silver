use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

use super::{
    AttestationsPane, Focus, Item,
    aggregates_panel::best,
    chart::{self, committee_color, dim, fg, secs},
    panel::{Panel, Row},
    votes_panel::spread,
};
use crate::sources::pq::TargetKey;

/// The header, one row per committee, the all row and the borders.
pub fn height(pane: &AttestationsPane) -> u16 {
    pane.data().slot(pane.slot).committees.len() as u16 + 4
}

pub fn draw(f: &mut Frame, area: Rect, pane: &mut AttestationsPane) {
    let info = pane.data().slot(pane.slot);
    let time = &pane.data().time;
    let header = format!(
        "  {:<10}{:>11}{:>8}{:>8}{:>6} │ {:>10}{:>8}{:>12} │ {:>11}",
        "committee", "votes", "median", "p90", ">att", "aggregates", "first", "best", "our proof"
    );
    let fixed = vec![(Line::styled(header, Style::default().add_modifier(Modifier::BOLD)), None)];

    let mut list: Vec<Row> = Vec::new();
    for committee in 0..info.committees.len() as u8 {
        let size = usize::from(info.committees[usize::from(committee)]);
        if size == 0 {
            continue;
        }
        let marker = if pane.committee_filter == Some(committee) { "● " } else { "  " };
        let mut spans = vec![Span::styled(marker, fg(Color::Cyan))];
        spans.extend(spread(
            &format!("c{committee}"),
            &chart::vote_times(pane, Some(committee)),
            size,
            time,
        ));
        spans[1] = spans[1].clone().style(fg(committee_color(committee)));
        spans.push(Span::styled(" │ ", dim()));
        spans.extend(aggregates(pane, Some(committee), size));
        spans.push(Span::styled(" │ ", dim()));
        spans.push(our_proof(pane, committee));
        list.push((Line::from(spans), Some(Item::Committee(committee))));
    }
    let mut all = vec![Span::raw("  ")];
    all.extend(spread("all", &chart::vote_times(pane, None), info.members(), time));
    all.push(Span::styled(" │ ", dim()));
    all.extend(aggregates(pane, None, info.members()));
    list.push((Line::from(all).style(fg(Color::Gray)), None));

    let aggregates = (pane.data().aggregates_of(pane.slot).iter())
        .filter(|&&index| pane.seen(pane.data().aggregates[index].received))
        .count();
    let summary =
        format!("{} votes · {aggregates} aggregates", chart::vote_times(pane, None).len());
    let panel = Panel { title: "committees", summary, fixed, list };
    panel.draw(f, area, pane.focus == Focus::Committees, &mut pane.committees);
}

/// Count and first arrival, ours included, and the members any of them covers.
fn aggregates(pane: &AttestationsPane, committee: Option<u8>, size: usize) -> Vec<Span<'static>> {
    let all: Vec<_> = (pane.data().aggregates_of(pane.slot).iter())
        .map(|&index| &pane.data().aggregates[index])
        .filter(|aggregate| committee.is_none_or(|only| aggregate.committee == only))
        .filter(|aggregate| pane.seen(aggregate.received))
        .collect();
    let covered: usize = match committee {
        Some(committee) => best(pane, committee),
        None => (0..pane.data().slot(pane.slot).committees.len() as u8)
            .map(|committee| best(pane, committee))
            .sum(),
    };
    if all.is_empty() {
        return vec![Span::styled(format!("{:>10}", 0), dim())];
    }
    let first = all.iter().map(|aggregate| aggregate.received).fold(f64::INFINITY, f64::min);
    let first = secs(pane.rel(first));
    vec![
        Span::raw(format!("{:>10}", all.len())),
        Span::raw(format!("{first:>8}")),
        Span::raw(format!("{:>12}", format!("{covered}/{size}"))),
    ]
}

fn our_proof(pane: &AttestationsPane, committee: u8) -> Span<'static> {
    let target = pane.data().targets_of(pane.slot).find(|&target| {
        matches!(pane.data().targets[target].key, TargetKey::Aggregate { committee: held, .. } if held == committee)
    });
    let Some(target) = target else { return Span::styled(format!("{:>11}", "no duty"), dim()) };
    let read = pane.data().targets[target].read.min(pane.now);
    let (proven, arrived) = (pane.data().proven(target, read), pane.data().available(target, read));
    let color = if proven == arrived { Color::Green } else { Color::Red };
    Span::styled(format!("{:>11}", format!("{proven}/{arrived}")), fg(color))
}
