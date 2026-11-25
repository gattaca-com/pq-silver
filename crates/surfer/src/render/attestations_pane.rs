use std::iter;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::Line,
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table},
};

use crate::{
    app::App,
    sources::attestations::{Arrivals, AttestationArrivals, BIN_MS},
};

const BINS_PER_SEC: usize = (1_000 / BIN_MS) as usize;
const ARRIVAL_COLOR: Color = Color::Cyan;
const RELAYED_COLOR: Color = Color::Yellow;
const LOCAL_COLOR: Color = Color::Green;
const BARS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
/// Slot, total, late, first and peak, with their spacing.
const FIXED_COLUMNS: u16 = 10 + 9 + 7 + 8 + 15 + 5;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    if app.attestations.all.total() == 0 {
        let block = Block::default().borders(Borders::ALL).title(" attestations ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no pq attestation arrivals yet")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }
    // `None` is the row of every slot together.
    app.attestations_display_order = iter::once(None)
        .chain(app.attestations.slots().iter().rev().map(|held| Some(held.slot)))
        .collect();
    if !app.attestations_display_order.contains(&app.attestations_selected) {
        app.attestations_selected = None;
    }

    if app.drilled_in {
        draw_plot(f, area, app);
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(app.split_pct),
            Constraint::Percentage(100 - app.split_pct),
        ])
        .split(area);
    draw_table(f, rows[0], app);
    draw_plot(f, rows[1], app);
}

/// Maps bins onto terminal columns: whole bins per column, or whole columns
/// per bin.
struct Scale {
    merge: usize,
    repeat: usize,
}

impl Scale {
    fn new(bins: usize, width: usize) -> Self {
        let bins = bins.max(1);
        Self { merge: bins.div_ceil(width.max(1)), repeat: (width / bins).max(1) }
    }

    fn columns(&self, bins: &[u32]) -> Vec<u64> {
        bins.chunks(self.merge)
            .flat_map(|chunk| {
                let sum = chunk.iter().map(|&count| u64::from(count)).sum();
                iter::repeat_n(sum, self.repeat)
            })
            .collect()
    }
}

fn selected(source: &AttestationArrivals, row: Option<u64>) -> Option<&Arrivals> {
    row.map_or(Some(&source.all), |slot| source.slot(slot))
}

fn row_label(row: Option<u64>) -> String {
    row.map_or_else(|| "all".to_string(), |slot| slot.to_string())
}

fn bin_start_secs(bin: usize) -> f64 {
    (bin as u64 * BIN_MS) as f64 / 1_000.0
}

fn bars(arrivals: &Arrivals, width: usize) -> String {
    let columns = Scale::new(arrivals.bins.len(), width).columns(&arrivals.bins);
    let max = columns.iter().copied().max().unwrap_or(0).max(1);
    let bar = |&count: &u64| BARS[(count * (BARS.len() as u64 - 1)).div_ceil(max) as usize];
    columns.iter().map(bar).collect()
}

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let slot_secs = app.attestations.all.bins.len() / BINS_PER_SEC;
    let title =
        format!(" attestations — verified pq votes by time into their slot, per {BIN_MS} ms ");
    let block = Block::default().borders(Borders::ALL).title(title);
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let header = Row::new(vec![
        Cell::from("slot").style(bold),
        Cell::from("total").style(bold),
        Cell::from("late").style(bold),
        Cell::from("first").style(bold),
        Cell::from("peak").style(bold),
        Cell::from(format!("0s → {slot_secs}s")).style(bold.fg(ARRIVAL_COLOR)),
    ])
    .height(1);

    let bars_width = area.width.saturating_sub(FIXED_COLUMNS + 2) as usize;
    let rows: Vec<Row> =
        app.attestations_display_order
            .iter()
            .map(|&row| {
                let arrivals = selected(&app.attestations, row).unwrap_or(&app.attestations.all);
                let first = arrivals.bins.iter().position(|&count| count > 0);
                let peak = (arrivals.bins.iter().enumerate())
                    .max_by_key(|&(bin, &count)| (count, usize::MAX - bin))
                    .filter(|&(_, &count)| count > 0);
                let style = if row == app.attestations_selected {
                    Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(row_label(row)),
                    Cell::from(format!("{:>7}", arrivals.total())),
                    Cell::from(format!("{:>5}", arrivals.late)),
                    Cell::from(first.map_or_else(
                        || "·".to_string(),
                        |bin| format!("{:.1}s", bin_start_secs(bin)),
                    )),
                    Cell::from(peak.map_or_else(
                        || "·".to_string(),
                        |(bin, count)| format!("{count} @ {:.1}s", bin_start_secs(bin)),
                    )),
                    Cell::from(bars(arrivals, bars_width))
                        .style(Style::default().fg(ARRIVAL_COLOR)),
                ])
                .height(1)
                .style(style)
            })
            .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(15),
        Constraint::Min(0),
    ];
    let table = Table::new(rows, widths).header(header).block(block);
    let position = app
        .attestations_display_order
        .iter()
        .position(|&row| row == app.attestations_selected)
        .unwrap_or(0);
    app.attestations_table_state.select(Some(position));
    f.render_stateful_widget(table, area, &mut app.attestations_table_state);
}

/// Count per bin against the bin's midpoint, in seconds into the slot.
fn series(arrivals: Option<&Arrivals>) -> Vec<(f64, f64)> {
    let bins = arrivals.map_or(&[][..], |arrivals| &arrivals.bins);
    bins.iter()
        .enumerate()
        .map(|(bin, &count)| (bin_start_secs(bin) + BIN_MS as f64 / 2_000.0, f64::from(count)))
        .collect()
}

fn draw_plot(f: &mut Frame, area: Rect, app: &App) {
    let row = app.attestations_selected;
    let sources = [
        ("arrival", ARRIVAL_COLOR, &app.attestations),
        ("relayed", RELAYED_COLOR, &app.attestations_relayed),
        ("local", LOCAL_COLOR, &app.attestations_local),
    ];
    let lines = sources.map(|(name, color, source)| {
        let arrivals = selected(source, row);
        let total = arrivals.map_or(0, Arrivals::total);
        (format!("{name} {total}"), color, series(arrivals))
    });

    let title = format!(" slot {} — votes per {BIN_MS} ms by time into the slot ", row_label(row));
    let slot_secs = (app.attestations.all.bins.len() / BINS_PER_SEC) as f64;
    let peak = lines.iter().flat_map(|(.., data)| data).map(|&(_, y)| y).fold(1.0, f64::max);
    let datasets = lines
        .iter()
        .map(|(name, color, data)| {
            Dataset::default()
                .name(name.as_str())
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(*color))
                .graph_type(GraphType::Line)
                .data(data)
        })
        .collect();

    let axis = Style::default().fg(Color::DarkGray);
    let chart = Chart::new(datasets)
        .block(Block::default().borders(Borders::ALL).title(title))
        .x_axis(Axis::default().bounds([0.0, slot_secs]).style(axis).labels(vec![
            Line::from("0s"),
            Line::from(format!("{}s", slot_secs / 2.0)),
            Line::from(format!("{slot_secs}s")),
        ]))
        .y_axis(Axis::default().bounds([0.0, peak]).style(axis).labels(vec![
            Line::from("0"),
            Line::from(format!("{}", (peak / 2.0).round())),
            Line::from(format!("{peak}")),
        ]));
    f.render_widget(chart, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bins_spread_over_wide_areas_and_merge_into_narrow_ones() {
        let bins = [1, 2, 3, 4];
        let wide = Scale::new(bins.len(), 9);
        assert_eq!(wide.columns(&bins), [1, 1, 2, 2, 3, 3, 4, 4]);

        let narrow = Scale::new(bins.len(), 3);
        assert_eq!(narrow.columns(&bins), [3, 7]);
    }

    #[test]
    fn a_series_point_sits_at_its_bin_midpoint() {
        let mut bins = vec![0; 8];
        bins[7] = 3;
        let arrivals = Arrivals { bins, late: 0 };
        assert_eq!(series(Some(&arrivals))[7], (0.75, 3.0));
        assert!(series(None).is_empty());
    }
}
