use std::ops::Range;

use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};

const GUIDE_CHARS: [char; 3] = ['┊', '┃', '│'];
/// Background of time a proof can no longer take votes from.
pub const BAND: Color = Color::Rgb(95, 45, 55);

/// Maps milliseconds into the slot onto plot columns.
#[derive(Clone, Copy)]
pub struct Axis {
    pub from: f64,
    pub to: f64,
    pub width: usize,
}

impl Axis {
    pub fn ms_per_col(&self) -> f64 {
        (self.to - self.from) / self.width.max(1) as f64
    }

    /// Column `c` stands for the time around `c` column widths into the
    /// window. Points and spans share that rounding, so a marker lands inside
    /// the bar of the moment it marks, and touching spans touch on screen.
    pub fn col(&self, ms: f64) -> Option<usize> {
        if self.width == 0 || ms < self.from || ms >= self.to {
            return None;
        }
        Some((((ms - self.from) / self.ms_per_col()).round() as usize).min(self.width - 1))
    }

    /// At least one column for any span that overlaps the window.
    pub fn cols(&self, from: f64, to: f64) -> Option<Range<usize>> {
        if self.width == 0 || to < self.from || from >= self.to {
            return None;
        }
        let boundary = |ms: f64| {
            (((ms - self.from) / self.ms_per_col()).round().max(0.0) as usize).min(self.width)
        };
        let start = boundary(from).min(self.width - 1);
        Some(start..boundary(to).max(start + 1))
    }

    pub fn tick_step(&self) -> f64 {
        const STEPS: [f64; 8] = [100.0, 200.0, 500.0, 1_000.0, 2_000.0, 4_000.0, 6_000.0, 12_000.0];
        let min_cols = 7.0;
        STEPS.into_iter().find(|step| step / self.ms_per_col() >= min_cols).unwrap_or(12_000.0)
    }
}

pub struct Guide {
    pub ms: f64,
    pub ch: char,
    pub style: Style,
    pub label: Option<String>,
}

pub struct Strip {
    cells: Vec<(char, Style)>,
}

impl Strip {
    pub fn new(width: usize) -> Self {
        Self { cells: vec![(' ', Style::default()); width] }
    }

    /// Empty or a guide, possibly on the band.
    pub fn is_blank(&self, col: usize) -> bool {
        self.cells.get(col).is_some_and(|&(ch, style)| {
            (ch == ' ' || GUIDE_CHARS.contains(&ch)) && style.bg.is_none_or(|bg| bg == BAND)
        })
    }

    pub fn bg(&self, col: usize) -> Option<Color> {
        self.cells.get(col).and_then(|&(_, style)| style.bg)
    }

    pub fn get(&self, col: usize) -> Option<char> {
        self.cells.get(col).map(|&(ch, _)| ch)
    }

    /// Keeps the cell's background unless `style` sets one.
    pub fn set(&mut self, col: usize, ch: char, style: Style) {
        if let Some(cell) = self.cells.get_mut(col) {
            *cell = (ch, cell.1.patch(style));
        }
    }

    pub fn fill(&mut self, cols: Range<usize>, ch: char, style: Style) {
        for col in cols {
            self.set(col, ch, style);
        }
    }

    pub fn guides(&mut self, axis: &Axis, guides: &[Guide]) {
        for guide in guides {
            if let Some(col) = axis.col(guide.ms) &&
                self.is_blank(col)
            {
                self.set(col, guide.ch, guide.style);
            }
        }
    }

    /// Writes `text` at `col` if every cell it needs is blank.
    pub fn text(&mut self, col: usize, text: &str, style: Style) -> bool {
        let len = text.chars().count();
        if col + len > self.cells.len() || !(col..col + len).all(|col| self.is_blank(col)) {
            return false;
        }
        for (offset, ch) in text.chars().enumerate() {
            self.set(col + offset, ch, style);
        }
        true
    }

    pub fn cursor(&mut self, axis: &Axis, ms: Option<f64>) {
        let Some(col) = ms.and_then(|ms| axis.col(ms)) else { return };
        if self.is_blank(col) {
            self.set(col, '│', Style::default().fg(Color::Yellow));
        } else {
            self.set(col, self.cells[col].0, Style::default().bg(Color::Rgb(120, 120, 40)));
        }
    }

    pub fn spans(self) -> Vec<Span<'static>> {
        let mut spans: Vec<Span> = Vec::new();
        let mut run = String::new();
        let mut style = Style::default();
        for (ch, cell_style) in self.cells {
            if cell_style != style && !run.is_empty() {
                spans.push(Span::styled(std::mem::take(&mut run), style));
            }
            style = cell_style;
            run.push(ch);
        }
        if !run.is_empty() {
            spans.push(Span::styled(run, style));
        }
        spans
    }
}

/// Pads or truncates spans to exactly `width` columns.
pub fn fit(spans: Vec<Span<'static>>, width: usize) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let mut used = 0;
    for span in spans {
        let len = span.content.chars().count();
        if used + len <= width {
            used += len;
            out.push(span);
            continue;
        }
        let keep: String = span.content.chars().take(width - used).collect();
        used = width;
        out.push(Span::styled(keep, span.style));
        break;
    }
    if used < width {
        out.push(Span::raw(" ".repeat(width - used)));
    }
    out
}

/// A row on the shared time grid: label gutter, plot, right gutter.
pub fn aligned(
    left: Vec<Span<'static>>,
    strip: Strip,
    right: Vec<Span<'static>>,
    left_width: usize,
    right_width: usize,
) -> Line<'static> {
    let mut spans = fit(left, left_width);
    spans.extend(strip.spans());
    spans.push(Span::raw(" "));
    spans.extend(fit(right, right_width - 1));
    Line::from(spans)
}
