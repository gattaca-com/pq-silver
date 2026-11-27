//! PQ attestations: votes and aggregates as they arrive, and what leanVM
//! proved from them, one slot at a time.

use std::{collections::HashSet, path::Path};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use flux::timing::Nanos;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_stages::SlotClock;

use self::{
    chart::{dim, secs},
    page::Page,
};
use crate::sources::pq::{PqData, PqSource};

mod aggregates_panel;
mod chart;
mod committees_panel;
mod page;
mod panel;
mod strip;
mod votes_panel;

const SELECTED: Style = Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD);

/// A selectable row in one of the parts.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Item {
    Committee(u8),
    Vote(usize),
    Aggregate(usize),
    Target(usize),
    Job(usize),
}

#[derive(Clone, Copy)]
pub enum Enter {
    ShowCommittee(u8),
    ShowAllCommittees,
    FindInTable { index: usize, committee: u8 },
    ShowMerge { job: usize, select: Item },
    Expand(Item),
    Collapse(Item),
}

impl Enter {
    pub fn label(self) -> &'static str {
        match self {
            Self::ShowCommittee(_) => "only this committee",
            Self::ShowAllCommittees => "all committees",
            Self::FindInTable { .. } => "go to table",
            Self::ShowMerge { .. } => "go to leanVM merge",
            Self::Expand(_) => "expand",
            Self::Collapse(_) => "collapse",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Timeline,
    Committees,
    Votes,
    Aggregates,
}

/// The selectable rows of one part as last drawn, and where it is scrolled.
#[derive(Default)]
pub struct Rows {
    pub items: Vec<Item>,
    pub selected: usize,
    pub scroll: usize,
    /// Rows the part showed; a page moves by that many.
    pub visible: usize,
    /// Selected once the next draw lists it.
    pending: Option<Item>,
}

impl Rows {
    pub fn set(&mut self, items: Vec<Item>, visible: usize) {
        self.items = items;
        self.visible = visible;
        if let Some(item) = self.pending.take() &&
            let Some(position) = self.items.iter().position(|&listed| listed == item)
        {
            self.selected = position;
        }
        self.selected = self.selected.min(self.items.len().saturating_sub(1));
    }

    pub fn selected_item(&self) -> Option<Item> {
        self.items.get(self.selected).copied()
    }

    /// Keeps `line`, the selection's line, in view with `context` lines around
    /// it.
    pub fn follow(&mut self, line: usize, height: usize, context: usize) {
        if line < self.scroll + context {
            self.scroll = line.saturating_sub(context);
        } else if line + context + 1 > self.scroll + height {
            self.scroll = line + context + 1 - height;
        }
    }

    fn reset(&mut self) {
        self.selected = 0;
        self.scroll = 0;
    }

    fn step(&mut self, rows: isize) {
        self.selected =
            self.selected.saturating_add_signed(rows).min(self.items.len().saturating_sub(1));
    }

    fn page(&self) -> isize {
        self.visible.saturating_sub(1).max(1) as isize
    }
}

pub struct AttestationsPane {
    source: PqSource,
    pub slot: u64,
    /// Follows the slot under way.
    pub follow: bool,
    /// Milliseconds since genesis; nothing later has been seen.
    pub now: f64,
    /// Into the selected slot, in milliseconds.
    pub window: (f64, f64),
    pub focus: Focus,
    pub timeline: Rows,
    pub committees: Rows,
    pub votes: Rows,
    pub aggregates: Rows,
    pub expanded: HashSet<Item>,
    pub committee_filter: Option<u8>,
}

impl AttestationsPane {
    pub fn open(base_dir: &Path, clock: &SlotClock, gloas: bool) -> Self {
        let source = PqSource::open(base_dir, clock, gloas);
        let window = (0.0, source.data().time.slot_ms);
        Self {
            source,
            slot: 0,
            follow: true,
            now: 0.0,
            window,
            focus: Focus::Timeline,
            timeline: Rows::default(),
            committees: Rows::default(),
            votes: Rows::default(),
            aggregates: Rows::default(),
            expanded: HashSet::new(),
            committee_filter: None,
        }
    }

    pub fn data(&self) -> &PqData {
        self.source.data()
    }

    pub fn sample(&mut self, now: Nanos) {
        self.source.sample(now);
        self.now = self.data().time.ms(now);
        let current = self.current_slot();
        if self.follow && current != self.slot {
            self.select_slot(current);
        }
    }

    pub fn current_slot(&self) -> u64 {
        self.data().time.slot_at(self.now)
    }

    /// Into the selected slot.
    pub fn rel(&self, ms: f64) -> f64 {
        ms - self.data().time.slot_start(self.slot)
    }

    pub fn seen(&self, ms: f64) -> bool {
        ms <= self.now
    }

    fn focused(&self) -> &Rows {
        match self.focus {
            Focus::Timeline => &self.timeline,
            Focus::Committees => &self.committees,
            Focus::Votes => &self.votes,
            Focus::Aggregates => &self.aggregates,
        }
    }

    fn focused_mut(&mut self) -> &mut Rows {
        match self.focus {
            Focus::Timeline => &mut self.timeline,
            Focus::Committees => &mut self.committees,
            Focus::Votes => &mut self.votes,
            Focus::Aggregates => &mut self.aggregates,
        }
    }

    /// The selection of `focus`, when that part has the keys.
    pub fn highlight(&self, focus: Focus) -> Option<Item> {
        (self.focus == focus).then(|| self.focused().selected_item()).flatten()
    }

    /// The selected moment, drawn as a cursor through every time row.
    pub fn cursor(&self) -> Option<f64> {
        let data = self.data();
        let ms = match self.focused().selected_item()? {
            Item::Vote(index) => data.votes.get(index)?.received,
            Item::Aggregate(index) => data.aggregates.get(index)?.received,
            Item::Job(job) => data.jobs.get(job)?.sent,
            Item::Committee(_) | Item::Target(_) => return None,
        };
        Some(self.rel(ms))
    }

    fn select_slot(&mut self, slot: u64) {
        self.slot = slot;
        self.timeline.reset();
        self.committees.reset();
        self.votes.reset();
        self.aggregates.reset();
        self.expanded.clear();
        if self.committee_filter.is_some_and(|committee| {
            usize::from(committee) >= self.data().slot(slot).committees.len()
        }) {
            self.committee_filter = None;
        }
    }

    fn step_slot(&mut self, dir: i64) {
        let slot = self.slot.saturating_add_signed(dir).min(self.current_slot());
        self.follow = slot == self.current_slot();
        self.select_slot(slot);
    }

    /// A committee row filters every part to it; a target or job expands.
    /// From a table, a vote or aggregate opens the proof that took it; from a
    /// proof, an aggregate goes to its row in the table.
    pub fn enter_action(&self) -> Option<Enter> {
        let enter = match self.focused().selected_item()? {
            Item::Committee(committee) if self.committee_filter == Some(committee) => {
                Enter::ShowAllCommittees
            }
            Item::Committee(committee) => Enter::ShowCommittee(committee),
            Item::Aggregate(index) if self.focus == Focus::Timeline => {
                let committee = self.data().aggregates.get(index)?.committee;
                Enter::FindInTable { index, committee }
            }
            Item::Aggregate(index) => {
                let (job, _) = self.data().aggregates.get(index)?.used_in?;
                Enter::ShowMerge { job, select: Item::Aggregate(index) }
            }
            Item::Vote(index) => {
                let vote = self.data().votes.get(index)?;
                let job = vote.proved_by.or(vote.block_job)?;
                Enter::ShowMerge { job, select: Item::Job(job) }
            }
            item if self.expanded.contains(&item) => Enter::Collapse(item),
            item => Enter::Expand(item),
        };
        Some(enter)
    }

    fn enter(&mut self) {
        let Some(enter) = self.enter_action() else { return };
        match enter {
            Enter::ShowCommittee(committee) => self.committee_filter = Some(committee),
            Enter::ShowAllCommittees => self.committee_filter = None,
            Enter::FindInTable { index, committee } => {
                if self.committee_filter.is_some_and(|only| only != committee) {
                    self.committee_filter = None;
                }
                self.focus = Focus::Aggregates;
                self.aggregates.pending = Some(Item::Aggregate(index));
            }
            Enter::ShowMerge { job, select } => self.open_job(job, select),
            Enter::Expand(item) => {
                self.expanded.insert(item);
            }
            Enter::Collapse(item) => {
                self.expanded.remove(&item);
            }
        }
    }

    /// Shows `job`'s inputs in the timeline and selects `select` there.
    fn open_job(&mut self, job: usize, select: Item) {
        let Some(target) = self.data().jobs.get(job).map(|job| job.target) else { return };
        self.expanded.insert(Item::Target(target));
        self.expanded.insert(Item::Job(job));
        self.focus = Focus::Timeline;
        self.timeline.pending = Some(select);
    }

    fn focus_on(&mut self, focus: Focus) {
        self.focus = if self.focus == focus { Focus::Timeline } else { focus };
    }

    /// Out to the slots a block proof spans, and back.
    fn zoom(&mut self, factor: f64) {
        let slot_ms = self.data().time.slot_ms;
        let max = 4.0 * slot_ms;
        let span = ((self.window.1 - self.window.0) * factor).clamp(slot_ms / 12.0, max);
        let center = self.cursor().unwrap_or(span / 2.0);
        let from = (center - span / 2.0).clamp(0.0, max - span);
        self.window = (from, from + span);
    }

    /// Returns whether the pane used the key.
    pub fn on_key(&mut self, key: KeyEvent) -> bool {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let page = self.focused().page();
        match key.code {
            KeyCode::Left => self.step_slot(-1),
            KeyCode::Right => self.step_slot(1),
            KeyCode::Up if shift => self.focused_mut().step(-page),
            KeyCode::Down if shift => self.focused_mut().step(page),
            KeyCode::Up => self.focused_mut().step(-1),
            KeyCode::Down => self.focused_mut().step(1),
            KeyCode::PageUp => self.focused_mut().step(-page),
            KeyCode::PageDown => self.focused_mut().step(page),
            KeyCode::Char('u') if control => self.focused_mut().step(-page / 2),
            KeyCode::Char('d') if control => self.focused_mut().step(page / 2),
            KeyCode::Home => self.focused_mut().selected = 0,
            KeyCode::End => {
                let rows = self.focused_mut();
                rows.selected = rows.items.len().saturating_sub(1);
            }
            KeyCode::Char('c') => self.focus_on(Focus::Committees),
            KeyCode::Char('v') => self.focus_on(Focus::Votes),
            KeyCode::Char('a') => self.focus_on(Focus::Aggregates),
            KeyCode::Esc => self.focus = Focus::Timeline,
            KeyCode::Enter => self.enter(),
            KeyCode::Char('+') | KeyCode::Char('=') => self.zoom(0.5),
            KeyCode::Char('-') => self.zoom(2.0),
            _ => return false,
        }
        true
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let [page, side] = Layout::horizontal([
            Constraint::Min(0),
            Constraint::Length(votes_panel::WIDTH + aggregates_panel::WIDTH),
        ])
        .areas(area);
        let [committees, tables] = Layout::vertical([
            Constraint::Length(committees_panel::height(self)),
            Constraint::Min(0),
        ])
        .areas(side);
        let [votes, aggregates] =
            Layout::horizontal([Constraint::Length(votes_panel::WIDTH), Constraint::Min(0)])
                .areas(tables);
        committees_panel::draw(f, committees, self);
        votes_panel::draw(f, votes, self);
        aggregates_panel::draw(f, aggregates, self);
        self.draw_timeline(f, page);
    }

    fn draw_timeline(&mut self, f: &mut Frame, area: Rect) {
        let into = self.now - self.data().time.slot_start(self.current_slot());
        let state = if self.follow {
            Span::styled(format!("● live {} ", secs(into)), Style::default().fg(Color::Green))
        } else {
            Span::styled(format!("live slot {} ", self.current_slot()), dim())
        };
        let mut title = vec![
            Span::raw(" attestations — "),
            Span::styled("◂ ", dim()),
            Span::styled(
                format!("slot {}", self.slot),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(" ▸", dim()),
            Span::raw(format!("  epoch {}", self.slot / SLOTS_PER_EPOCH)),
        ];
        if self.slot.is_multiple_of(SLOTS_PER_EPOCH) {
            title.push(Span::styled("  epoch boundary", Style::default().fg(Color::Yellow)));
        }
        let border = if self.focus == Focus::Timeline {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border)
            .title(Line::from(title))
            .title(Line::from(state).alignment(Alignment::Right));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let lines = Page::build(self, usize::from(inner.width));
        let height = usize::from(inner.height);
        self.timeline.set(lines.iter().filter_map(|(_, item)| *item).collect(), height);
        let selected = self.highlight(Focus::Timeline);
        if let Some(line) = lines.iter().position(|(_, item)| item.is_some() && *item == selected) {
            self.timeline.follow(line, height, 2);
        }
        self.timeline.scroll = self.timeline.scroll.min(lines.len().saturating_sub(height));
        let visible: Vec<Line> =
            lines
                .into_iter()
                .skip(self.timeline.scroll)
                .take(height)
                .map(|(line, item)| {
                    if item.is_some() && item == selected {
                        line.patch_style(SELECTED)
                    } else {
                        line
                    }
                })
                .collect();
        f.render_widget(Paragraph::new(visible), inner);
    }
}
