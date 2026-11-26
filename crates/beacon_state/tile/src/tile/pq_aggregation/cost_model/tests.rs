use super::*;

/// Seconds per term of the synthetic box: a shape unlike the defaults.
const TRUTH: [f64; TERMS] = [0.3, 0.5, 0.25, 0.005, 0.000_05];

/// A fixed pseudo-random sequence, so every run sees the same samples.
struct Noise(u64);

impl Noise {
    /// In `[0, 1)`.
    fn next(&mut self) -> f64 {
        self.0 =
            self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() * bound as f64) as usize
    }

    fn shape(&mut self) -> MergeShape {
        let proofs = self.below(4);
        let (idle, signatures, claims) = (self.next() < 0.3, self.below(300), self.below(2_000));
        MergeShape { idle, proofs, signatures, claims_in: proofs * claims, request_bytes: 0 }
    }

    /// The round trip of `shape` on a box costing `truth`, with up to 5% noise.
    fn round_trip(&mut self, truth: &[f64; TERMS], shape: &MergeShape) -> Nanos {
        Nanos::from_secs_f64(dot(truth, &shape.features()) * (0.95 + 0.1 * self.next()))
    }
}

fn feed(model: &mut CostModel, truth: &[f64; TERMS], count: usize, noise: &mut Noise) {
    feed_shapes(model, truth, count, noise, Noise::shape);
}

fn feed_shapes(
    model: &mut CostModel,
    truth: &[f64; TERMS],
    count: usize,
    noise: &mut Noise,
    shape: impl Fn(&mut Noise) -> MergeShape,
) {
    for _ in 0..count {
        let shape = shape(noise);
        let predicted = model.predict(&shape);
        let round_trip = noise.round_trip(truth, &shape);
        model.record(&shape, predicted, round_trip);
    }
}

/// A cold aggregate proof, an extension, and two proof-only merges.
fn probes() -> [MergeShape; 4] {
    let shape = |idle, proofs, signatures, claims_in| MergeShape {
        idle,
        proofs,
        signatures,
        claims_in,
        request_bytes: 0,
    };
    [
        shape(true, 0, 40, 0),
        shape(false, 1, 120, 300),
        shape(false, 9, 0, 5_000),
        shape(false, 2, 0, 3_000),
    ]
}

fn seconds(model: &CostModel) -> [f64; 4] {
    probes().map(|probe| model.predict(&probe).as_secs())
}

/// The mean relative error over shapes like those sampled, on a box costing
/// `truth`. The prior keeps it above the noise when `truth` is far from the
/// defaults in shape.
fn error(model: &CostModel, truth: &[f64; TERMS]) -> f64 {
    let (mut noise, count) = (Noise(97), 200);
    let errors = (0..count).map(|_| {
        let shape = noise.shape();
        (model.predict(&shape).as_secs() / dot(truth, &shape.features()) - 1.0).abs()
    });
    errors.sum::<f64>() / count as f64
}

fn scaled(costs: &[f64; TERMS], factor: f64) -> [f64; TERMS] {
    costs.map(|seconds| seconds * factor)
}

#[test]
fn an_empty_window_predicts_the_defaults() {
    let model = CostModel::default();
    for probe in probes() {
        let defaults = Nanos::from_secs_f64(dot(&DEFAULT_SECONDS, &probe.features()));
        assert_eq!(model.predict(&probe), defaults);
    }
}

#[test]
fn the_scale_of_the_defaults_does_not_matter() {
    let predictions = [0.1, 1.0, 10.0].map(|factor| {
        let mut model = CostModel::new(scaled(&DEFAULT_SECONDS, factor));
        feed(&mut model, &TRUTH, WINDOW, &mut Noise(7));
        seconds(&model)
    });
    for other in &predictions[1..] {
        for (left, right) in predictions[0].iter().zip(other) {
            assert!((left - right).abs() < 0.005, "{left} against {right}");
        }
    }
}

#[test]
fn predictions_follow_a_change_of_speed_within_one_window() {
    for factor in [3.0, 1.0 / 3.0] {
        let (mut model, mut noise) = (CostModel::default(), Noise(11));
        feed(&mut model, &TRUTH, 2 * WINDOW, &mut noise);
        assert!(error(&model, &TRUTH) < 0.1);
        let changed = scaled(&TRUTH, factor);
        feed(&mut model, &changed, WINDOW, &mut noise);
        assert!(error(&model, &changed) < 0.1, "factor {factor}: {}", error(&model, &changed));
    }
}

#[test]
fn one_slow_request_raises_the_margin_until_it_leaves_the_window() {
    let (mut model, mut noise) = (CostModel::default(), Noise(13));
    feed(&mut model, &TRUTH, WINDOW, &mut noise);
    let shape = noise.shape();
    let predicted = model.predict(&shape);
    model.record(&shape, predicted, predicted * 3u64);
    assert!(model.margin() > 3.0 - 1e-9, "{}", model.margin());

    feed(&mut model, &TRUTH, WINDOW, &mut noise);
    assert!(model.margin() < 1.5, "{}", model.margin());
}

#[test]
fn a_term_never_sampled_stays_at_its_scaled_default() {
    let (mut model, mut noise) = (CostModel::default(), Noise(17));
    let without_claims = |noise: &mut Noise| MergeShape { claims_in: 0, ..noise.shape() };
    feed_shapes(&mut model, &TRUTH, WINDOW, &mut noise, without_claims);
    let expected = model.scale * DEFAULT_SECONDS[CLAIM];
    let fitted = model.coefficients[CLAIM];
    assert!((fitted / expected - 1.0).abs() < 1e-9, "{fitted} against {expected}");
}

#[test]
fn a_cost_that_falls_with_signatures_never_lowers_a_prediction() {
    // Each signature saves time, so a fit without the clamp prices it below zero.
    let truth = [2.0, 0.0, 0.3, -0.006, 0.0];
    let (mut model, mut noise) = (CostModel::default(), Noise(19));
    let without_claims = |noise: &mut Noise| MergeShape { claims_in: 0, ..noise.shape() };
    feed_shapes(&mut model, &truth, WINDOW, &mut noise, without_claims);
    let without_signatures = MergeShape { signatures: 0, ..probes()[1] };
    let with_signatures = MergeShape { signatures: 300, ..without_signatures };
    let without = model.predict(&without_signatures);
    let with = model.predict(&with_signatures);
    assert!(without > Nanos::ZERO && with > Nanos::ZERO);
    assert!(with >= without, "{with:?} < {without:?}");
}

#[test]
fn collinear_samples_keep_the_total_right() {
    let (mut model, mut noise) = (CostModel::default(), Noise(23));
    let one_proof = |noise: &mut Noise| MergeShape { proofs: 1, idle: false, ..noise.shape() };
    feed_shapes(&mut model, &TRUTH, WINDOW, &mut noise, one_proof);
    let probe =
        MergeShape { idle: false, proofs: 1, signatures: 150, claims_in: 1_000, request_bytes: 0 };
    let (predicted, actual) = (model.predict(&probe).as_secs(), dot(&TRUTH, &probe.features()));
    assert!((predicted / actual - 1.0).abs() < 0.05, "{predicted} against {actual}");
}

#[test]
fn degenerate_samples_never_give_a_non_finite_prediction() {
    let mut model = CostModel::default();
    let empty =
        MergeShape { idle: false, proofs: 0, signatures: 0, claims_in: 0, request_bytes: 0 };
    model.record(&empty, model.predict(&empty), Nanos::ZERO);

    model.record(&empty, Nanos::ZERO, Nanos::from_millis(300));
    model.record(&empty, model.predict(&empty), Nanos::from_millis(300));
    assert!(seconds(&model).into_iter().all(f64::is_finite));
    assert!(model.predict(&empty) > Nanos::ZERO);
    assert!(model.margin().is_finite());

    let mut model = CostModel::new([0.25, 0.45, 0.2, 0.004, 1e-300]);
    let shape =
        MergeShape { idle: false, proofs: 1, signatures: 10, claims_in: 100, request_bytes: 0 };
    let before = model.predict(&shape);
    model.record(&shape, before, Nanos::from_millis(500));
    assert_eq!(model.predict(&shape), before, "a fit that is not finite is not adopted");
}

/// A model with a full window, and a request in flight with its prediction.
fn in_flight() -> (CostModel, MergeShape, Nanos) {
    let (mut model, mut noise) = (CostModel::default(), Noise(37));
    feed(&mut model, &TRUTH, WINDOW, &mut noise);
    let shape = noise.shape();
    let predicted = model.predict(&shape);
    (model, shape, predicted)
}

#[test]
fn a_request_past_its_plan_raises_every_plan_with_its_elapsed_time() {
    let (mut model, _, predicted) = in_flight();
    let other = probes()[1];
    let prediction = model.predict(&other);
    let longest = model.longest_round_trip().unwrap();
    for factor in [3u64, 5] {
        assert!(model.overdue(predicted, predicted * factor));
        let ratio = model.planned(&other).as_secs() / prediction.as_secs();
        assert!((ratio - factor as f64).abs() < 1e-6, "{ratio}");
        assert_eq!(model.predict(&other), prediction);
        assert_eq!(model.longest_round_trip(), Some(longest));
    }
    assert!(predicted * 5u64 > longest, "the overdue request would change the history");
}

#[test]
fn a_request_within_its_plan_leaves_the_margin() {
    let (mut model, _, predicted) = in_flight();
    let margin = model.margin();
    assert!(!model.overdue(predicted, predicted));
    assert!(!model.overdue(Nanos::ZERO, predicted), "no prediction");
    assert_eq!(model.margin(), margin);
}

#[test]
fn the_answer_of_an_overdue_request_keeps_its_margin_as_a_sample() {
    let (mut model, shape, predicted) = in_flight();
    assert!(model.overdue(predicted, predicted * 3u64));
    model.record(&shape, predicted, predicted * 4u64);
    assert!(model.margin() >= 4.0 - 1e-9, "{}", model.margin());
}

#[test]
fn a_slow_request_without_a_proof_holds_the_margin_until_the_next_sample() {
    let (mut model, _, predicted) = in_flight();
    assert!(model.overdue(predicted, predicted * 3u64));
    let shape = probes()[0];
    let next = model.predict(&shape);
    assert!((model.margin() - 3.0).abs() < 1e-9, "the request gave no sample");
    model.record(&shape, next, next);
    assert!(model.margin() < 1.5, "{}", model.margin());
}
