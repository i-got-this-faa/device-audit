"""Paired window and event metrics for the ML05 device bootstrap."""

from dataclasses import dataclass
import math

import numpy as np


@dataclass(frozen=True)
class ScoredWindow:
    device: str
    label: int
    lead_days: int
    logit: float
    smart: int | None


def operating_point(scores, target):
    """Lowest observed cutoff whose inclusive alerts fit the negative budget.

    If the next score's entire tie group would exceed the budget, use the next
    representable cutoff above it. Integer SMART scores retain exact ties.
    """
    ordered = sorted((score for score in scores if score is not None), reverse=True)
    index = math.floor(target * len(scores))
    if not ordered:
        return None
    if index >= len(ordered):
        return ordered[-1]
    excluded = ordered[index]
    return excluded + 1 if isinstance(excluded, int) else math.nextafter(excluded, math.inf)


class Ranking:
    def __init__(self, groups, labels):
        # Ascending integer ranks with one bin per distinct score.
        self.groups = groups
        self.labels = labels
        self.size = int(groups.max()) + 1

    def counts(self, weights):
        positive = np.bincount(self.groups, weights * self.labels, minlength=self.size)
        total = np.bincount(self.groups, weights, minlength=self.size)
        return positive, total

    @staticmethod
    def metrics(positive, total, positives, negatives):
        # Average precision uses a whole tie group at each cutoff. AUC gives
        # half credit when a positive and negative window tie.
        tp = np.cumsum(positive[::-1])
        predicted = np.cumsum(total[::-1])
        precision = np.divide(tp, predicted, out=np.zeros_like(tp), where=predicted > 0)
        ap = np.sum(precision * positive[::-1]) / positives
        negative = total - positive
        auc = np.sum(positive * (np.cumsum(negative) - 0.5 * negative)) / (positives * negatives)
        return float(ap), float(auc)


def calibration_slope(logits, positive, total):
    """Unpenalized binomial logistic regression with a free intercept."""
    active = total > 0
    x, y, n = logits[active], positive[active], total[active]
    prevalence = y.sum() / n.sum()
    if len(x) < 2 or not 0.0 < prevalence < 1.0:
        return None

    positive_scores = x[y > 0]
    negative_scores = x[y < n]
    if positive_scores.min() >= negative_scores.max() or negative_scores.min() >= positive_scores.max():
        return None  # Complete or quasi-complete separation has no finite fit.

    # Center and scale the predictor for the two-parameter Newton solve.
    center = np.sum(n * x) / n.sum()
    x = x - center
    scale = math.sqrt(np.sum(n * x * x) / n.sum())
    if not scale:
        return None
    x /= scale
    intercept, slope = math.log(prevalence / (1.0 - prevalence)), 0.0
    for _ in range(50):
        z = intercept + slope * x
        loss = np.sum(y * np.logaddexp(0, -z) + (n - y) * np.logaddexp(0, z))
        p = np.exp(-np.logaddexp(0, -z))
        q = np.exp(-np.logaddexp(0, z))
        residual = y * q - (n - y) * p
        curvature = n * p * q
        a, b, c = curvature.sum(), np.sum(curvature * x), np.sum(curvature * x * x)
        determinant = a * c - b * b
        if determinant <= 0:
            return None
        ra, rb = residual.sum(), np.sum(residual * x)
        delta_a = (c * ra - b * rb) / determinant
        delta_b = (a * rb - b * ra) / determinant
        if max(abs(delta_a), abs(delta_b)) < 1e-8:
            return float(slope / scale)
        for step in (0.5 ** power for power in range(20)):
            candidate = z + step * (delta_a + delta_b * x)
            candidate_loss = np.sum(y * np.logaddexp(0, -candidate)
                                    + (n - y) * np.logaddexp(0, candidate))
            if candidate_loss <= loss:
                intercept += step * delta_a
                slope += step * delta_b
                break
        else:
            return None
    return None


class Metrics:
    def __init__(self, rows, prevalence, degraded, critical, smart_cutoff, horizon_days):
        devices = sorted({row.device for row in rows})
        device_index = {device: i for i, device in enumerate(devices)}
        self.device_count = len(devices)
        self.device = np.asarray([device_index[row.device] for row in rows])
        labels = np.asarray([row.label for row in rows])
        logits = np.asarray([row.logit for row in rows])
        self.logits, groups = np.unique(logits, return_inverse=True)
        self.ranking = Ranking(groups, labels)
        smart_scores = sorted({row.smart for row in rows if row.smart is not None})
        smart_rank = {score: i + 1 for i, score in enumerate(smart_scores)}
        self.smart_ranking = Ranking(np.asarray([smart_rank.get(row.smart, 0) for row in rows]), labels)
        alerts = logits >= degraded
        self.prevalence = prevalence
        self.negative = self.by_device(1 - labels)
        self.positive = self.by_device(labels)
        self.false_degraded = self.by_device((labels == 0) & alerts)
        self.false_critical = self.by_device((labels == 0) & (logits >= critical))
        self.never_positive = self.positive == 0
        self.false_device = self.never_positive & (self.false_degraded > 0)
        p = np.exp(-np.logaddexp(0, -logits))
        self.expected = self.by_device(p)
        self.brier_error = self.by_device((p - labels) ** 2)
        self.prevalence_error = self.by_device((prevalence - labels) ** 2)

        # A positive label binds the first event for that device. Take the
        # largest lead (earliest alert) among its eligible positive windows.
        self.events = self.positive > 0
        self.first_lead = np.zeros(self.device_count, dtype=int)
        for row, device, alert in zip(rows, self.device, alerts):
            if row.label and alert:
                self.first_lead[device] = max(self.first_lead[device], row.lead_days)
        self.lead_bins = horizon_days + 1
        smart_alert = [row.label and row.smart is not None and smart_cutoff is not None
                       and row.smart >= smart_cutoff for row in rows]
        self.smart_detected = self.by_device(smart_alert) > 0

    def by_device(self, weights):
        return np.bincount(self.device, weights, minlength=self.device_count)

    def measure(self, device_weights):
        def count(values):
            return float(np.sum(device_weights * values))

        positives, negatives = count(self.positive), count(self.negative)
        events = count(self.events)
        never_positive = count(self.never_positive)
        leads = np.bincount(self.first_lead, device_weights, minlength=self.lead_bins)[1:]
        detected = int(leads.sum())
        median = None
        if detected:
            cumulative = np.cumsum(leads)
            middle = np.searchsorted(cumulative, [(detected - 1) // 2 + 1, detected // 2 + 1])
            median = float(middle.mean() + 1)

        ap = auc = smart_ap = prevalence_ap = slope = None
        if positives and negatives:
            weights = device_weights[self.device]
            positive, total = self.ranking.counts(weights)
            ap, auc = self.ranking.metrics(positive, total, positives, negatives)
            smart_ap, _ = self.smart_ranking.metrics(*self.smart_ranking.counts(weights), positives, negatives)
            prevalence_ap = positives / (positives + negatives)
            slope = calibration_slope(self.logits, positive, total)
        recall = detected / events if events else None
        smart_recall = count(self.smart_detected) / events if events else None
        prevalence_error = count(self.prevalence_error)
        return {
            "average_precision": ap,
            "smart_rule_average_precision": smart_ap,
            "prevalence_average_precision": prevalence_ap,
            "average_precision_minus_best_baseline": ap - max(smart_ap, prevalence_ap) if ap is not None else None,
            "smart_rule_event_recall": smart_recall,
            "event_recall_minus_smart_rule": recall - smart_recall if events else None,
            "roc_auc": auc,
            "window_false_positive_rate_degraded": count(self.false_degraded) / negatives if negatives else None,
            "window_false_positive_rate_critical": count(self.false_critical) / negatives if negatives else None,
            "never_positive_device_alert_fraction": count(self.false_device) / never_positive if never_positive else None,
            "brier_skill_vs_prevalence": 1 - count(self.brier_error) / prevalence_error if prevalence_error else None,
            # Probabilities predict window labels, so the ratio uses observed
            # positive windows and their expected count on the same scale.
            "observed_to_expected_ratio": positives / count(self.expected),
            "calibration_slope": slope,
            "event_recall_within_horizon": recall,
            "median_first_alert_lead_days": median,
        }


def bootstrap(metrics, procedure):
    point = metrics.measure(np.ones(metrics.device_count))
    draws = {metric: [] for metric in point}
    rng = np.random.Generator(np.random.PCG64(procedure["seed"]))
    for _ in range(procedure["replicates"]):
        devices = rng.integers(metrics.device_count, size=metrics.device_count)
        sample = metrics.measure(np.bincount(devices, minlength=metrics.device_count))
        for metric, value in sample.items():
            if value is not None and math.isfinite(value):
                draws[metric].append(value)

    tail = (1 - procedure["interval"]) / 2
    result = {}
    for metric, value in point.items():
        lower, upper = (map(float, np.quantile(draws[metric], [tail, 1 - tail]))
                        if draws[metric] else (None, None))
        result[metric] = {"point": value, "lower": lower, "upper": upper,
                          "defined_replicates": len(draws[metric])}
    return result
