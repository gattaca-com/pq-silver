use std::collections::BTreeMap;

use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

use super::{
    AttestationsPane, Item,
    chart::{
        self, BLOCK_JOB_COLOR, FAILED_COLOR, JOB_COLOR, PROVING_COLOR, REJECTED_COLOR,
        committee_color, dim, exact, fg, swatch, target_name,
    },
    strip::{Axis, Guide, Strip, aligned},
};
use crate::sources::pq::{JobOutcome, Member, TargetKey};

pub const LEFT: usize = 32;
pub const RIGHT: usize = 20;

const READ_STYLE: Style = Style::new().fg(Color::White).add_modifier(Modifier::BOLD);

pub type PageLine = (Line<'static>, Option<Item>);

fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// The whole tab as one scrolling document, every time row on one axis.
pub struct Page<'a> {
    pane: &'a AttestationsPane,
    axis: Axis,
    guides: Vec<Guide>,
    cursor: Option<f64>,
    lines: Vec<PageLine>,
}

impl<'a> Page<'a> {
    pub fn build(pane: &'a AttestationsPane, width: usize) -> Vec<PageLine> {
        let axis = Axis {
            from: pane.window.0,
            to: pane.window.1,
            width: width.saturating_sub(LEFT + RIGHT),
        };
        let mut page = Self {
            pane,
            axis,
            guides: chart::guides(pane),
            cursor: pane.cursor(),
            lines: Vec::new(),
        };
        page.votes();
        page.blank();
        page.leanvm();
        page.lines
    }

    fn push(&mut self, line: Line<'static>, item: Option<Item>) {
        self.lines.push((line, item));
    }

    fn blank(&mut self) {
        self.push(Line::default(), None);
    }

    fn timed(
        &mut self,
        left: Vec<Span<'static>>,
        mut strip: Strip,
        right: Vec<Span<'static>>,
        item: Option<Item>,
    ) {
        strip.guides(&self.axis, &self.guides);
        strip.cursor(&self.axis, self.cursor);
        self.push(aligned(left, strip, right, LEFT, RIGHT), item);
    }

    fn arrow(&self, item: Item) -> &'static str {
        if self.pane.expanded.contains(&item) { "▾ " } else { "▸ " }
    }

    fn votes(&mut self) {
        let pane = self.pane;
        let times = chart::vote_times(pane, pane.committee_filter);
        let per = format!("votes arriving per {:.0} ms", chart::bin_ms(&self.axis));
        let mut legend = vec![Span::raw(format!("{per} by committee: "))];
        if let Some(only) = pane.committee_filter {
            legend.extend(swatch(committee_color(only), &format!("c{only} only")));
        } else {
            let committees = pane.data().slot(pane.slot).committees.len() as u8;
            for committee in 0..committees.min(chart::COMMITTEE_COLOURS) {
                legend.extend(swatch(committee_color(committee), &format!("c{committee}")));
            }
            if committees > chart::COMMITTEE_COLOURS {
                legend.push(Span::styled(
                    format!("colours repeat from c{}   ", chart::COMMITTEE_COLOURS),
                    dim(),
                ));
            }
        }
        legend.push(Span::raw("◆ aggregate received  ◇ ours   "));
        legend.push(Span::styled("│ ", fg(Color::Green)));
        legend.push(Span::raw("now"));
        self.push(Line::from(legend), None);
        self.push(
            aligned(
                vec![],
                chart::group_labels(&self.axis, &pane.data().time),
                vec![],
                LEFT,
                RIGHT,
            ),
            None,
        );

        let labels = chart::labels(&self.axis, &self.guides);
        self.push(aligned(vec![], labels, vec![], LEFT, RIGHT), None);
        for (row, strip) in chart::histogram(pane, &self.axis).into_iter().enumerate() {
            let left = if row == 0 { vec![Span::styled("votes arriving", bold())] } else { vec![] };
            let right = match row {
                0 => vec![Span::styled(format!("{} votes", times.len()), bold())],
                1 => {
                    let beyond = times.iter().filter(|&&ms| ms >= self.axis.to).count();
                    if beyond > 0 {
                        vec![Span::styled(format!("+{beyond} later"), fg(Color::Red))]
                    } else {
                        vec![]
                    }
                }
                _ => vec![],
            };
            self.timed(left, strip, right, None);
        }
        let aggregates: Vec<f64> = (pane.data().aggregates_of(pane.slot).iter())
            .map(|&index| &pane.data().aggregates[index])
            .filter(|aggregate| pane.seen(aggregate.received))
            .filter(|aggregate| {
                pane.committee_filter.is_none_or(|only| only == aggregate.committee)
            })
            .map(|aggregate| pane.rel(aggregate.received))
            .collect();
        let beyond = aggregates.iter().filter(|&&ms| ms >= self.axis.to).count();
        let right = if beyond > 0 {
            vec![
                Span::styled(aggregates.len().to_string(), bold()),
                Span::raw(" · "),
                Span::styled(format!("+{beyond} later"), fg(Color::Red)),
            ]
        } else {
            vec![Span::styled(format!("{} aggregates", aggregates.len()), bold())]
        };
        self.timed(
            vec![Span::styled("aggregates received", bold())],
            chart::aggregate_dots(pane, &self.axis),
            right,
            None,
        );
        self.push(aligned(vec![], chart::ticks(&self.axis), vec![], LEFT, RIGHT), None);
    }

    fn leanvm(&mut self) {
        let pane = self.pane;
        // What the prover did during this slot, whichever slot's votes it was
        // proving: this slot's aggregate proofs, and any proof with a job or a
        // request in the window.
        let slot_start = pane.data().time.slot_start(pane.slot);
        let (from, to) = (slot_start + self.axis.from, slot_start + self.axis.to);
        let targets: Vec<usize> = (pane.data().targets.ids())
            .filter(|&target| {
                let held = &pane.data().targets[target];
                let own = held.slot == pane.slot && matches!(held.key, TargetKey::Aggregate { .. });
                let worked = (held.jobs.iter()).map(|&job| &pane.data().jobs[job]).any(|job| {
                    pane.seen(job.sent) && job.sent < to && job.answered.min(pane.now) > from
                });
                own || worked || (pane.seen(held.read) && (from..to).contains(&held.read))
            })
            .collect();
        let mut legend = vec![Span::raw("leanVM jobs: ")];
        legend.extend(swatch(JOB_COLOR, "aggregate proof"));
        legend.extend(swatch(BLOCK_JOB_COLOR, "block proof"));
        legend.extend(swatch(PROVING_COLOR, "proving"));
        legend.extend(swatch(FAILED_COLOR, "late"));
        legend.extend(swatch(REJECTED_COLOR, "failed"));
        legend.push(Span::styled("▼ ", READ_STYLE));
        legend.push(Span::raw("requested   "));
        legend.push(Span::styled("→ s+N ", dim()));
        legend.push(Span::raw("requested in a later slot   "));
        // The summary bar reuses the job colours for the votes those jobs held.
        legend.push(Span::styled("░ ", dim()));
        legend.push(Span::raw("votes not taken"));
        self.push(Line::from(legend), None);

        let groups = [
            ("votes → aggregate proof", "no aggregation duty in this slot"),
            ("aggregates + votes → block proof", "no block proof worked on in this slot"),
        ];
        for (block, (title, none)) in groups.into_iter().enumerate() {
            self.blank();
            let header = Line::from(vec![
                Span::styled(
                    format!("{title:<width$}", width = LEFT + self.axis.width + 1),
                    bold(),
                ),
                Span::styled("in proof / had", dim()),
            ]);
            self.push(header, None);
            let group: Vec<usize> = (targets.iter().copied())
                .filter(|&target| {
                    matches!(pane.data().targets[target].key, TargetKey::Block { .. }) ==
                        (block == 1)
                })
                .collect();
            if group.is_empty() {
                self.push(Line::styled(format!("  {none}"), dim()), None);
            }
            // Requested in this slot: what we gave. Then proofs this slot only
            // worked on, requested later.
            let (given, later): (Vec<usize>, Vec<usize>) =
                group.into_iter().partition(|&target| !requested_later(pane, target));
            for target in given {
                self.target_rows(target);
            }
            for target in later {
                self.target_rows(target);
            }
        }
        self.work_lane(from, to);
        self.push(aligned(vec![], chart::ticks(&self.axis), vec![], LEFT, RIGHT), None);
    }

    /// Every job the prover ran in the window, one bar each, coloured by
    /// the kind of proof it served.
    fn work_lane(&mut self, from: f64, to: f64) {
        let pane = self.pane;
        let mut strip = Strip::new(self.axis.width);
        let mut busy = 0.0;
        for job in pane.data().jobs.ids() {
            let held = &pane.data().jobs[job];
            let end = held.answered.min(pane.now);
            if !pane.seen(held.sent) || held.sent >= to || end <= from {
                continue;
            }
            busy += end.min(to).min(pane.now) - held.sent.max(from);
            let label = match pane.data().targets[held.target].key {
                TargetKey::Aggregate { committee, .. } => format!("c{committee}"),
                TargetKey::Block { block_slot } => format!("block {block_slot}"),
            };
            self.job_bar(&mut strip, job, label);
        }
        let span = (to.min(pane.now) - from).max(1.0);
        let right = vec![Span::raw(format!("busy {:.0}%", busy / span * 100.0))];
        self.blank();
        self.timed(vec![Span::styled("leanVM work", bold())], strip, right, None);
    }

    fn target_rows(&mut self, target: usize) {
        let pane = self.pane;
        let held = &pane.data().targets[target];
        let item = Item::Target(target);
        let read = pane.seen(held.read);
        let end = held.read.min(pane.now);
        let jobs: Vec<usize> = held
            .jobs
            .iter()
            .copied()
            .filter(|&job| pane.seen(pane.data().jobs[job].sent))
            .collect();

        let mut strip = Strip::new(self.axis.width);
        for &job in &jobs {
            let added = pane.data().jobs[job].new_claims;
            let label = match (pane.data().jobs[job].new_aggregates(), held.key) {
                (aggregates, TargetKey::Block { .. }) if aggregates > 0 => {
                    match pane.data().jobs[job].new_votes() {
                        0 => format!("+{aggregates}a"),
                        votes => format!("+{aggregates}a +{votes}v"),
                    }
                }
                _ => format!("+{added}"),
            };
            self.job_bar(&mut strip, job, label);
        }
        // What the proof held when requested is what we gave. A proof
        // requested in a later slot is counted on that slot's page.
        let request_slot = pane.data().time.slot_at(held.read);
        let later = requested_later(pane, target);
        if !later {
            self.read_marker(&mut strip, held.read);
        }
        let right = if later {
            vec![Span::styled(format!("→ {}", slot_offset(pane, request_slot)), dim())]
        } else {
            self.coverage(target, end, read)
        };
        let left = vec![
            Span::raw(self.arrow(item)),
            Span::styled(format!("{:<16}", target_label(pane, target)), match held.key {
                _ if later => dim(),
                TargetKey::Aggregate { committee, .. } => fg(committee_color(committee)),
                TargetKey::Block { .. } => Style::default(),
            }),
            if read && !later {
                Span::styled(format!("▼ {}", exact(pane.rel(held.read))), READ_STYLE)
            } else {
                Span::raw("")
            },
        ];
        self.timed(left, strip, right, Some(item));

        if pane.expanded.contains(&item) {
            for job in jobs {
                self.job_row(job);
            }
        }
    }

    /// What became of the votes the target had by `end`: a bar split into in
    /// the proof, in a job that finished too late, and never taken, then the
    /// proof's count over what it had, over all the slots it takes from.
    fn coverage(&self, target: usize, end: f64, read: bool) -> Vec<Span<'static>> {
        let pane = self.pane;
        let had = pane.data().available(target, end);
        let proven = pane.data().proven(target, end).min(had);
        let late: usize = (pane.data().targets[target].jobs.iter())
            .map(|&job| &pane.data().jobs[job])
            .filter(|job| job.outcome == JobOutcome::Late && pane.seen(job.answered))
            .map(|job| job.new_claims)
            .sum::<usize>()
            .min(had - proven);
        let count = if read { fg(Color::White) } else { fg(Color::Cyan) };
        votes_bar(proven, late, had, count.add_modifier(Modifier::BOLD))
    }

    /// The proof as this job left it.
    fn job_coverage(&self, job: usize) -> Vec<Span<'static>> {
        let pane = self.pane;
        let held = &pane.data().jobs[job];
        let end = held.answered.min(pane.now).min(pane.data().targets[held.target].read);
        let proven = pane.data().proven(held.target, held.answered.min(pane.now));
        let had = pane.data().available(held.target, end).max(proven);
        let late = if held.outcome == JobOutcome::Late { held.new_claims } else { 0 };
        votes_bar(proven, late.min(had - proven), had, Style::default())
    }

    fn job_row(&mut self, job: usize) {
        let pane = self.pane;
        let held = &pane.data().jobs[job];
        let mut strip = Strip::new(self.axis.width);
        let round_trip = pane.now.min(held.answered) - held.sent;
        self.job_bar(&mut strip, job, format!("{round_trip:.0}ms"));
        self.write_failure(&mut strip, job);
        self.read_marker(&mut strip, pane.data().targets[held.target].read);
        let end =
            if pane.seen(held.answered) { exact(pane.rel(held.answered)) } else { "…".into() };
        let span = format!("{}–{end}", exact(pane.rel(held.sent)).trim_end_matches('s'));
        let late = pane.seen(held.answered) && held.outcome != JobOutcome::Ok;
        let item = Item::Job(job);
        // The span sits under the target's request time, so the two compare at a
        // glance.
        let left = vec![
            Span::raw(format!("  {}", self.arrow(item))),
            Span::styled(format!("{:<14}", format!("#{}", held.id)), dim()),
            Span::styled(span, if late { fg(Color::Red) } else { Style::default() }),
        ];
        let right = self.job_coverage(job);
        self.timed(left, strip, right, Some(item));
        if pane.expanded.contains(&item) {
            self.job_inputs(job);
        }
    }

    /// One row per input in arrival order, its time in the column under the
    /// job's span: when it arrived, or when the proof it builds on finished.
    fn job_inputs(&mut self, job: usize) {
        let pane = self.pane;
        let held = &pane.data().jobs[job];
        let mut aggregates: Vec<(usize, usize)> = Vec::new();
        let mut votes: Vec<usize> = Vec::new();
        for member in &held.members {
            match *member {
                Member::Running { job: previous, claims } => {
                    let answered = pane.data().jobs[previous].answered;
                    let mut strip = Strip::new(self.axis.width);
                    if let Some(col) = self.axis.col(pane.rel(answered)) {
                        strip.set(col, '●', fg(JOB_COLOR));
                    }
                    let left = input_label(
                        vec![Span::raw(format!("proof #{}", pane.data().jobs[previous].id))],
                        exact(pane.rel(answered)),
                    );
                    self.timed(
                        left,
                        strip,
                        vec![Span::styled(format!("{claims} held"), dim())],
                        None,
                    );
                }
                Member::Aggregate { index, gain } => aggregates.push((index, gain)),
                Member::Vote(index) => votes.push(index),
            }
        }
        // The selected slot's aggregates one by one; each other slot's in one row.
        let anchor = pane.data().targets[held.target].slot;
        let (own, other): (Vec<_>, Vec<_>) = aggregates
            .into_iter()
            .partition(|&(index, _)| pane.data().aggregates[index].slot == anchor);
        let mut other_slots: BTreeMap<u64, Vec<(usize, usize)>> = BTreeMap::new();
        for (index, gain) in other {
            other_slots.entry(pane.data().aggregates[index].slot).or_default().push((index, gain));
        }
        for (slot, group) in other_slots.into_iter().rev() {
            let mut strip = Strip::new(self.axis.width);
            for &(index, _) in &group {
                let aggregate = &pane.data().aggregates[index];
                if let Some(col) = self.axis.col(pane.rel(aggregate.received)) {
                    strip.set(col, '◆', dim());
                }
            }
            let name = vec![
                Span::raw(format!("{} aggregates", group.len())),
                Span::raw(format!(" {}", slot_offset(pane, slot))),
            ];
            let slot_start = pane.data().time.slot_start(slot);
            let times: Vec<f64> = group
                .iter()
                .map(|&(index, _)| pane.data().aggregates[index].received - slot_start)
                .collect();
            let first = times.iter().copied().fold(f64::INFINITY, f64::min);
            let last = times.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let span = format!("{}–{}", exact(first).trim_end_matches('s'), exact(last));
            let gain: usize = group.iter().map(|&(_, gain)| gain).sum();
            self.timed(input_label(name, span), strip, vec![Span::raw(format!("+{gain}"))], None);
        }
        for (index, gain) in own {
            let aggregate = &pane.data().aggregates[index];
            let color = committee_color(aggregate.committee);
            let mut strip = Strip::new(self.axis.width);
            let (at, time) = own_slot_time(pane, aggregate.slot, aggregate.received);
            let mark = if aggregate.slot == pane.slot { fg(color) } else { dim() };
            if let Some(col) = self.axis.col(at) {
                strip.set(col, if aggregate.local { '◇' } else { '◆' }, mark);
            }
            let from =
                if aggregate.local { "ours".to_string() } else { aggregate.aggregator.to_string() };
            let name = vec![
                Span::styled(format!("c{:<3}", aggregate.committee), fg(color)),
                Span::raw(format!("p{} ", aggregate.position)),
                Span::styled(format!("{from:<7}"), dim()),
            ];
            let shared = usize::from(aggregate.attesters).saturating_sub(gain);
            let mut right = vec![Span::raw(format!("+{gain}"))];
            if shared > 0 {
                right.push(Span::styled(format!(" · {shared} shared"), dim()));
            }
            self.timed(input_label(name, time), strip, right, Some(Item::Aggregate(index)));
        }
        let mut by_slot: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for &index in &votes {
            by_slot.entry(pane.data().votes[index].slot).or_default().push(index);
        }
        // The selected slot's votes first, then older slots'.
        let mut groups: Vec<(u64, Vec<usize>)> = by_slot.into_iter().collect();
        groups.sort_by_key(|&(slot, _)| (slot != pane.slot, std::cmp::Reverse(slot)));
        for (slot, group) in groups {
            let mut strip = Strip::new(self.axis.width);
            for &index in &group {
                let vote = &pane.data().votes[index];
                let mark =
                    if slot == pane.slot { fg(committee_color(vote.committee)) } else { dim() };
                if let Some(col) = self.axis.col(pane.rel(vote.received)) {
                    strip.set(col, '•', mark);
                }
            }
            let mut name = vec![Span::raw(format!("{} votes", group.len()))];
            if slot != pane.slot {
                name.push(Span::raw(format!(" {}", slot_offset(pane, slot))));
            }
            let left = input_label(name, vote_span(pane, slot, &group));
            self.timed(left, strip, vec![Span::raw(format!("+{}", group.len()))], None);
        }
        self.left_waiting(job, &votes);
    }

    /// A failed job's reason, written just after its bar; colour says the rest.
    fn write_failure(&self, strip: &mut Strip, job: usize) {
        let pane = self.pane;
        let held = &pane.data().jobs[job];
        let JobOutcome::Refused(reason) = held.outcome else { return };
        if !pane.seen(held.answered) {
            return;
        }
        let Some(bar) = self.axis.cols(pane.rel(held.sent), pane.rel(held.answered)) else {
            return
        };
        let len = reason.chars().count();
        // After the bar if it fits, else before it, else cut at the edge.
        let (start, text) = if bar.end + 1 + len <= self.axis.width {
            (bar.end + 1, reason.to_string())
        } else if bar.start > len {
            (bar.start - len - 1, reason.to_string())
        } else {
            (
                bar.end + 1,
                reason.chars().take(self.axis.width.saturating_sub(bar.end + 1)).collect(),
            )
        };
        strip.text(start, &text, fg(REJECTED_COLOR));
    }

    /// Votes an aggregate proof could have taken when `job` started but did
    /// not: verified by then, and in no earlier proof or this one.
    fn left_waiting(&mut self, job: usize, taken: &[usize]) {
        let pane = self.pane;
        let held = &pane.data().jobs[job];
        let target = &pane.data().targets[held.target];
        let TargetKey::Aggregate { committee, .. } = target.key else { return };
        let left: Vec<usize> = (pane.data().slot(target.slot).votes.iter().copied())
            .filter(|&index| {
                let vote = &pane.data().votes[index];
                vote.committee == committee &&
                    vote.received <= held.sent &&
                    !taken.contains(&index) &&
                    vote.proved_by
                        .is_none_or(|earlier| pane.data().jobs[earlier].sent > held.sent)
            })
            .collect();
        if left.is_empty() {
            return;
        }
        let mut strip = Strip::new(self.axis.width);
        for &index in &left {
            if let Some(col) = self.axis.col(pane.rel(pane.data().votes[index].received)) {
                strip.set(col, '◦', fg(committee_color(committee)));
            }
        }
        let left_label = input_label(
            vec![Span::raw(format!("{} left", left.len()))],
            vote_span(pane, pane.slot, &left),
        );
        self.timed(left_label, strip, vec![Span::styled("not taken", dim())], None);
    }

    /// A bar like the reference charts: a filled block, a thin divider where
    /// it touches the previous job, and its label inside when it fits.
    fn job_bar(&self, strip: &mut Strip, job: usize, label: String) {
        let pane = self.pane;
        let held = &pane.data().jobs[job];
        let color = match (pane.seen(held.answered), held.outcome) {
            (false, _) => PROVING_COLOR,
            (true, JobOutcome::Ok)
                if matches!(pane.data().targets[held.target].key, TargetKey::Block { .. }) =>
            {
                BLOCK_JOB_COLOR
            }
            (true, JobOutcome::Ok) => JOB_COLOR,
            (true, JobOutcome::Late) => FAILED_COLOR,
            (true, JobOutcome::Refused(_)) => REJECTED_COLOR,
        };
        let Some(cols) = self.axis.cols(pane.rel(held.sent), pane.rel(held.answered.min(pane.now)))
        else {
            return
        };
        let joined = cols.start > 0 &&
            strip.bg(cols.start - 1).is_some_and(|bg| {
                [JOB_COLOR, BLOCK_JOB_COLOR, PROVING_COLOR, FAILED_COLOR, REJECTED_COLOR]
                    .contains(&bg)
            });
        let fill = Style::default().bg(color);
        strip.fill(cols.clone(), ' ', fill);
        if joined {
            strip.set(cols.start, '▏', fill.fg(Color::Black));
        }
        // The label goes on whichever side of the request marker has room.
        let read = pane.data().targets[held.target].read;
        let split = pane
            .seen(read)
            .then(|| self.axis.col(pane.rel(read)))
            .flatten()
            .filter(|col| cols.contains(col));
        let parts = match split {
            Some(col) => [cols.start..col, col + 1..cols.end],
            None => [cols.clone(), 0..0],
        };
        let len = label.chars().count();
        if let Some(room) =
            parts.into_iter().filter(|part| part.len() >= len + 2).max_by_key(|part| part.len())
        {
            let start = room.start + (room.len() - len) / 2;
            for (offset, ch) in label.chars().enumerate() {
                strip.set(start + offset, ch, fill.fg(Color::Black).add_modifier(Modifier::BOLD));
            }
        }
    }

    /// `→` when the request falls after the window.
    fn read_marker(&self, strip: &mut Strip, read: f64) {
        if !self.pane.seen(read) {
            return;
        }
        let rel = self.pane.rel(read);
        if let Some(col) = self.axis.col(rel) {
            strip.set(col, '▼', READ_STYLE);
        } else if rel >= self.axis.to {
            strip.set(self.axis.width - 1, '→', READ_STYLE);
        }
    }
}

/// An input row's label: its name indented under the job, then its time in
/// the column where job rows show their span.
fn input_label(name: Vec<Span<'static>>, time: String) -> Vec<Span<'static>> {
    const TIME_COLUMN: usize = 18;
    let mut spans = vec![Span::raw("   ")];
    let used: usize = 3 + name.iter().map(|span| span.content.chars().count()).sum::<usize>();
    spans.extend(name);
    spans.push(Span::raw(" ".repeat(TIME_COLUMN.saturating_sub(used).max(1))));
    spans.push(Span::styled(time, dim()));
    spans
}

/// `s−2`: how many slots before the selected one `slot` is.
fn slot_offset(pane: &AttestationsPane, slot: u64) -> String {
    let offset = slot as i64 - pane.slot as i64;
    if offset < 0 { format!("s−{}", -offset) } else { format!("s+{offset}") }
}

/// Where on the axis an input of `slot` arriving at `ms` sits: always on the
/// selected slot's clock. Its label: into the selected slot, or tagged and
/// into its own slot.
fn own_slot_time(pane: &AttestationsPane, slot: u64, ms: f64) -> (f64, String) {
    let into = ms - pane.data().time.slot_start(slot);
    let label = if slot == pane.slot {
        exact(into)
    } else {
        format!("{} {}", slot_offset(pane, slot), exact(into))
    };
    (pane.rel(ms), label)
}

/// A block is named by its slot; another slot's aggregate proof is tagged.
fn target_label(pane: &AttestationsPane, target: usize) -> String {
    let held = &pane.data().targets[target];
    match held.key {
        TargetKey::Aggregate { .. } if held.slot != pane.slot => {
            format!("{} {}", target_name(held.key), slot_offset(pane, held.slot))
        }
        key => target_name(key),
    }
}

/// First and last arrival among `votes`, into `slot`; they need not be in
/// arrival order.
fn vote_span(pane: &AttestationsPane, slot: u64, votes: &[usize]) -> String {
    let slot_start = pane.data().time.slot_start(slot);
    let times = votes.iter().map(|&index| pane.data().votes[index].received - slot_start);
    let first = times.clone().fold(f64::INFINITY, f64::min);
    let last = times.fold(f64::NEG_INFINITY, f64::max);
    format!("{}–{}", exact(first).trim_end_matches('s'), exact(last))
}

/// Seven cells: in the proof, in a job that finished too late, never taken;
/// then the proof's votes over the votes it had.
fn votes_bar(proven: usize, late: usize, had: usize, count: Style) -> Vec<Span<'static>> {
    const CELLS: usize = 7;
    let cells = |votes: usize| (votes * CELLS).div_ceil(had.max(1)).min(CELLS);
    let (in_cells, late_cells) =
        (cells(proven), cells(proven + late).saturating_sub(cells(proven)));
    vec![
        Span::styled("█".repeat(in_cells), fg(JOB_COLOR)),
        Span::styled("█".repeat(late_cells), fg(FAILED_COLOR)),
        Span::styled("░".repeat(CELLS - in_cells - late_cells), dim()),
        Span::styled(format!(" {proven}/{had}"), count),
    ]
}

/// Requested in a slot after the selected one: counted on that slot's page.
fn requested_later(pane: &AttestationsPane, target: usize) -> bool {
    let read = pane.data().targets[target].read;
    read.is_finite() && pane.data().time.slot_at(read) > pane.slot
}
