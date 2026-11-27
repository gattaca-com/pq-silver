use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use super::{
    Item, Rows,
    chart::{dim, fg},
};

const SELECTED: Style = Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD);

pub type Row = (Line<'static>, Option<Item>);

/// A side table: rows that stay put above a list that scrolls.
pub struct Panel {
    pub title: &'static str,
    pub summary: String,
    pub fixed: Vec<Row>,
    pub list: Vec<Row>,
}

impl Panel {
    pub fn draw(self, f: &mut Frame, area: Rect, focused: bool, rows: &mut Rows) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(if focused { fg(Color::Cyan) } else { Style::default() })
            .title(Span::styled(
                format!(" {} ", self.title),
                Style::default().add_modifier(Modifier::BOLD),
            ))
            .title(Line::from(format!(" {} ", self.summary)).alignment(Alignment::Right));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let height = usize::from(inner.height).saturating_sub(self.fixed.len());
        let items = self.fixed.iter().chain(&self.list).filter_map(|(_, item)| *item).collect();
        rows.set(items, height);
        let selected = focused.then(|| rows.selected_item()).flatten();
        if let Some(line) =
            self.list.iter().position(|(_, item)| item.is_some() && *item == selected)
        {
            rows.follow(line, height, 0);
        }
        let highlight = |(line, item): Row| {
            if item.is_some() && item == selected { line.patch_style(SELECTED) } else { line }
        };
        let mut lines: Vec<Line> = self.fixed.into_iter().map(highlight).collect();
        lines.extend(self.list.into_iter().skip(rows.scroll).take(height).map(highlight));
        f.render_widget(Paragraph::new(lines), inner);
    }
}

pub fn rule(text: &str, width: u16) -> Row {
    (
        Line::styled(
            format!("{:─<width$}", format!("─ {text} "), width = usize::from(width) - 2),
            dim(),
        ),
        None,
    )
}
