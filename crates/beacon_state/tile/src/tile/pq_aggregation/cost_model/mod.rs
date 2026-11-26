use std::collections::VecDeque;

use silver_common::Nanos;

/// Merge, idle start, input proof, signature, claim of an input proof.
const TERMS: usize = 5;
const PROOF: usize = 2;
const SIGNATURE: usize = 3;
const CLAIM: usize = 4;
const WINDOW: usize = 32;
/// Seconds per term, from the devnet boxes. Once a request is answered only
/// their ratios matter: the fit scales them to the box.
const DEFAULT_SECONDS: [f64; TERMS] = [0.25, 0.45, 0.2, 0.004, 0.000_2];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct MergeShape {
    /// The request did not go out straight after a response.
    pub idle: bool,
    pub proofs: usize,
    pub signatures: usize,
    /// Summed over the input proofs.
    pub claims_in: usize,
    pub request_bytes: usize,
}

impl MergeShape {
    fn features(&self) -> [f64; TERMS] {
        let idle = f64::from(u8::from(self.idle));
        [1.0, idle, self.proofs as f64, self.signatures as f64, self.claims_in as f64]
    }
}

struct Sample {
    features: [f64; TERMS],
    seconds: f64,
    /// The round trip over the prediction made before the request went out.
    ratio: f64,
}

/// Fits up to `WINDOW` proof-producing requests with measurable round trips.
///
/// The fit minimises relative errors, pulled towards the defaults scaled to
/// the box, with the weight of one sample per term. So a term the window
/// never exercises stays at its scaled default.
pub(super) struct CostModel {
    /// Every term is positive, so the prior and the scale are defined.
    defaults: [f64; TERMS],
    window: VecDeque<Sample>,
    /// Seconds per term, at least zero.
    coefficients: [f64; TERMS],
    /// The median round trip over what the defaults predict.
    scale: f64,
    /// The largest round trip over its prediction in the window, at least 1.
    margin: f64,
    /// A floor under `margin`, from a request seen past its plan. It holds
    /// until the next sample, so it outlives a slow request that ends
    /// without a proof.
    overdue: f64,
}

impl Default for CostModel {
    fn default() -> Self {
        Self::new(DEFAULT_SECONDS)
    }
}

impl CostModel {
    fn new(defaults: [f64; TERMS]) -> Self {
        debug_assert!(defaults.iter().all(|&seconds| seconds > 0.0));
        let window = VecDeque::with_capacity(WINDOW);
        let coefficients = defaults;
        Self { defaults, window, coefficients, scale: 1.0, margin: 1.0, overdue: 1.0 }
    }

    pub(super) fn predict(&self, shape: &MergeShape) -> Nanos {
        Nanos::from_secs_f64(dot(&self.coefficients, &shape.features()))
    }

    pub(super) fn planned(&self, shape: &MergeShape) -> Nanos {
        Nanos::from_secs_f64(self.margin() * dot(&self.coefficients, &shape.features()))
    }

    pub(super) fn proof_seconds(&self, claims: usize) -> f64 {
        self.coefficients[PROOF] + self.coefficients[CLAIM] * claims as f64
    }

    pub(super) fn signature_seconds(&self) -> f64 {
        self.coefficients[SIGNATURE]
    }

    pub(super) fn longest_round_trip(&self) -> Option<Nanos> {
        let seconds = self.window.iter().map(|sample| sample.seconds);
        seconds.max_by(f64::total_cmp).map(Nanos::from_secs_f64)
    }

    /// The window's margin, raised by a request in flight past its plan.
    pub(super) fn margin(&self) -> f64 {
        self.margin.max(self.overdue)
    }

    /// Raises the margin to `elapsed / predicted` for a request still in
    /// flight, if that is larger: whether the request is past its plan. It
    /// adds no sample.
    pub(super) fn overdue(&mut self, predicted: Nanos, elapsed: Nanos) -> bool {
        let ratio = elapsed.as_secs() / predicted.as_secs();
        let raised = ratio.is_finite() && ratio > self.margin();
        if raised {
            self.overdue = ratio;
        }
        raised
    }

    /// A zero round trip is below the clock's resolution and has no relative
    /// error, so it is not recorded.
    pub(super) fn record(&mut self, shape: &MergeShape, predicted: Nanos, round_trip: Nanos) {
        let seconds = round_trip.as_secs();
        if seconds <= 0.0 {
            return;
        }
        if self.window.len() == WINDOW {
            self.window.pop_front();
        }
        let ratio = seconds / predicted.as_secs();
        self.window.push_back(Sample { features: shape.features(), seconds, ratio });
        self.overdue = 1.0;
        self.refit();
    }

    fn refit(&mut self) {
        let mut ratios: Vec<f64> = (self.window.iter())
            .map(|sample| sample.seconds / dot(&self.defaults, &sample.features))
            .collect();
        let middle = ratios.len() / 2;
        self.scale = *ratios.select_nth_unstable_by(middle, f64::total_cmp).1;
        let prior = self.defaults.map(|seconds| self.scale * seconds);
        let fitted = self.fit(&prior);
        if fitted.iter().all(|seconds| seconds.is_finite()) {
            self.coefficients = fitted;
        }
        self.margin = (self.window.iter())
            .map(|sample| sample.ratio)
            .filter(|ratio| ratio.is_finite())
            .fold(1.0, f64::max);
    }

    /// Solves with every coefficient free, then fixes the most negative one
    /// at zero and solves again, until none is negative.
    fn fit(&self, prior: &[f64; TERMS]) -> [f64; TERMS] {
        let mut clamped = [false; TERMS];
        loop {
            let solution = NormalEquations::new(&self.window, prior, &clamped).solve();
            let most_negative = (0..TERMS)
                .filter(|&term| solution[term] < 0.0)
                .min_by(|&left, &right| solution[left].total_cmp(&solution[right]));
            match most_negative {
                Some(term) => clamped[term] = true,
                None => return solution,
            }
        }
    }
}

/// `matrix · a = rhs` for the coefficients `a` minimising
/// `Σ ((a · x − t) / t)² + Σ_k ((a_k − p_k) / p_k)²` over the samples `(x, t)`
/// and the prior `p`, with the clamped coefficients fixed at zero.
struct NormalEquations {
    matrix: [[f64; TERMS]; TERMS],
    rhs: [f64; TERMS],
}

impl NormalEquations {
    fn new(window: &VecDeque<Sample>, prior: &[f64; TERMS], clamped: &[bool; TERMS]) -> Self {
        let mut matrix = [[0.0; TERMS]; TERMS];
        let mut rhs = [0.0; TERMS];
        for sample in window {
            let weighted = sample.features.map(|feature| feature / sample.seconds);
            for ((row, value), &left) in matrix.iter_mut().zip(&mut rhs).zip(&weighted) {
                for (cell, &right) in row.iter_mut().zip(&weighted) {
                    *cell += left * right;
                }
                *value += left;
            }
        }
        for term in 0..TERMS {
            matrix[term][term] += 1.0 / (prior[term] * prior[term]);
            rhs[term] += 1.0 / prior[term];
            if clamped[term] {
                matrix[term] = [0.0; TERMS];
                matrix.iter_mut().for_each(|row| row[term] = 0.0);
                matrix[term][term] = 1.0;
                rhs[term] = 0.0;
            }
        }
        Self { matrix, rhs }
    }

    /// Gaussian elimination with partial pivoting. The prior makes the
    /// matrix positive definite, so no pivot is zero.
    fn solve(mut self) -> [f64; TERMS] {
        for column in 0..TERMS {
            let pivot = (column..TERMS)
                .max_by(|&a, &b| {
                    self.matrix[a][column].abs().total_cmp(&self.matrix[b][column].abs())
                })
                .unwrap_or(column);
            self.matrix.swap(column, pivot);
            self.rhs.swap(column, pivot);
            let (pivot_row, pivot_rhs) = (self.matrix[column], self.rhs[column]);
            for row in column + 1..TERMS {
                let factor = self.matrix[row][column] / pivot_row[column];
                let cells = self.matrix[row].iter_mut().zip(&pivot_row).skip(column);
                cells.for_each(|(cell, &pivot)| *cell -= factor * pivot);
                self.rhs[row] -= factor * pivot_rhs;
            }
        }
        let mut solution = [0.0; TERMS];
        for row in (0..TERMS).rev() {
            let known: f64 =
                (row + 1..TERMS).map(|term| self.matrix[row][term] * solution[term]).sum();
            solution[row] = (self.rhs[row] - known) / self.matrix[row][row];
        }
        solution
    }
}

fn dot(coefficients: &[f64; TERMS], features: &[f64; TERMS]) -> f64 {
    coefficients.iter().zip(features).map(|(coefficient, feature)| coefficient * feature).sum()
}

#[cfg(test)]
mod tests;
