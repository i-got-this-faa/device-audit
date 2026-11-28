package federated

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const (
	// WeightingPolicySampleCountV1 averages compatible vectors weighted by local sample_count.
	WeightingPolicySampleCountV1 = "sample-count-weighted.v1"
	// GenericCandidateSchemaV1 wraps aggregated parameters for non-logistic base artifacts.
	GenericCandidateSchemaV1 = "device-audit.federated-candidate.v1"
	// LogisticBaselineSchemaV1 matches ML02 models/src/device_audit_models/baseline.py.
	LogisticBaselineSchemaV1 = "device-audit.logistic-baseline.v1"

	aggregationInputDomain = "device-audit/federated-aggregation/v1\x00"
)

// AggregationInputSHA256 computes a canonical SHA-256 commitment over the round
// identity, base artifact digest, declared weighting policy, and sorted
// accepted participant inputs.
func AggregationInputSHA256(round contracts.FederatedRoundV1, policy string, participants []AggregatedParticipant) (string, uint64, error) {
	if err := round.Validate(); err != nil {
		return "", 0, err
	}
	if policy != WeightingPolicySampleCountV1 {
		return "", 0, fmt.Errorf("%w: unsupported weighting policy %q", ErrAggregationInvalid, policy)
	}
	sorted := slices.Clone(participants)
	slices.SortFunc(sorted, func(a, b AggregatedParticipant) int {
		return strings.Compare(a.DeviceID, b.DeviceID)
	})
	var totalSamples uint64
	seen := make(map[string]bool, len(sorted))
	for _, p := range sorted {
		if seen[p.DeviceID] || p.DeviceID == "" || p.SigningKeyID == "" || p.Sequence < 2 || p.SampleCount == 0 {
			return "", 0, fmt.Errorf("%w: invalid participant provenance for %q", ErrAggregationInvalid, p.DeviceID)
		}
		seen[p.DeviceID] = true
		if totalSamples > math.MaxUint64-uint64(p.SampleCount) {
			return "", 0, fmt.Errorf("%w: sample count overflow", ErrAggregationFailed)
		}
		totalSamples += uint64(p.SampleCount)
	}
	fields := []string{
		round.DeploymentID,
		round.RoundID,
		round.CandidateID,
		round.BaseModelVersion,
		round.BaseModelSHA256,
		round.FeatureVersion,
		strconv.FormatUint(uint64(round.ParameterCount), 10),
		policy,
		strconv.Itoa(len(sorted)),
		strconv.FormatUint(totalSamples, 10),
	}
	for _, p := range sorted {
		fields = append(fields,
			p.DeviceID,
			p.SigningKeyID,
			strconv.FormatUint(p.Sequence, 10),
			strconv.FormatUint(uint64(p.SampleCount), 10),
			p.UpdateSHA256,
			p.RequestSHA256,
		)
	}
	var buf bytes.Buffer
	buf.WriteString(aggregationInputDomain)
	for _, field := range fields {
		buf.Write(binary.BigEndian.AppendUint32(nil, uint32(len(field))))
		buf.WriteString(field)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), totalSamples, nil
}

// WeightedAverage aggregates compatible persisted participant updates using
// WeightingPolicySampleCountV1 in sorted device order with Shewchuk summation,
// matching models/src/device_audit_models/federated.py.
func WeightedAverage(round contracts.FederatedRoundV1, updates []AcceptedUpdate) ([]float64, uint64, error) {
	if len(updates) == 0 {
		return nil, 0, ErrNoUpdates
	}
	sorted := slices.Clone(updates)
	slices.SortFunc(sorted, func(a, b AcceptedUpdate) int {
		return strings.Compare(a.DeviceID, b.DeviceID)
	})
	var totalSamples uint64
	seen := make(map[string]bool, len(sorted))
	for _, u := range sorted {
		if seen[u.DeviceID] {
			return nil, 0, fmt.Errorf("%w: duplicate participant %s", ErrAggregationFailed, u.DeviceID)
		}
		seen[u.DeviceID] = true
		if u.RoundID != round.RoundID || u.DeploymentID != round.DeploymentID ||
			u.CandidateID != round.CandidateID || u.BaseModelVersion != round.BaseModelVersion ||
			u.BaseModelSHA256 != round.BaseModelSHA256 || u.FeatureVersion != round.FeatureVersion ||
			u.ParameterCount != round.ParameterCount || uint32(len(u.Weights)) != round.ParameterCount {
			return nil, 0, fmt.Errorf("%w: incompatible update from %s", ErrAggregationFailed, u.DeviceID)
		}
		if u.SampleCount == 0 {
			return nil, 0, fmt.Errorf("%w: zero sample count from %s", ErrAggregationFailed, u.DeviceID)
		}
		for _, w := range u.Weights {
			if math.IsNaN(w) || math.IsInf(w, 0) {
				return nil, 0, fmt.Errorf("%w: nonfinite weight from %s", ErrAggregationFailed, u.DeviceID)
			}
		}
		if totalSamples > math.MaxUint64-uint64(u.SampleCount) {
			return nil, 0, fmt.Errorf("%w: sample count overflow", ErrAggregationFailed)
		}
		totalSamples += uint64(u.SampleCount)
	}

	totalF := float64(totalSamples)
	out := make([]float64, round.ParameterCount)
	terms := make([]float64, len(sorted))
	for i := range out {
		for j, u := range sorted {
			term := u.Weights[i] * (float64(u.SampleCount) / totalF)
			if math.IsNaN(term) || math.IsInf(term, 0) {
				return nil, 0, fmt.Errorf("%w: nonfinite weighted term", ErrAggregationFailed)
			}
			terms[j] = term
		}
		sum, err := exactFloat64Sum(terms)
		if err != nil || math.IsNaN(sum) || math.IsInf(sum, 0) {
			return nil, 0, fmt.Errorf("%w: aggregated weight is not finite", ErrAggregationFailed)
		}
		out[i] = sum
	}
	return out, totalSamples, nil
}

// exactFloat64Sum mirrors Python's math.fsum (Shewchuk adaptive expansion) so
// Go and Python federated averaging produce matching binary64 values.
func exactFloat64Sum(xs []float64) (float64, error) {
	partials := make([]float64, 0, 8)
	for _, x := range xs {
		i := 0
		for _, y := range partials {
			if math.Abs(x) < math.Abs(y) {
				x, y = y, x
			}
			hi := x + y
			if math.IsInf(hi, 0) {
				return 0, errors.New("float64 overflow")
			}
			lo := y - (hi - x)
			if lo != 0 {
				partials[i] = lo
				i++
			}
			x = hi
		}
		partials = partials[:i]
		if x != 0 {
			partials = append(partials, x)
		}
	}
	n := len(partials)
	if n == 0 {
		return 0, nil
	}
	hi := partials[n-1]
	if n == 1 {
		return hi, nil
	}
	// Exact final rounding step mirroring CPython Objects/floatobject.c _fsum.
	lo := 0.0
	for i := n - 2; i >= 0; i-- {
		x := hi
		y := partials[i]
		hi = x + y
		lo = y - (hi - x)
		if lo != 0 {
			if i > 0 && ((lo < 0 && partials[i-1] < 0) || (lo > 0 && partials[i-1] > 0)) {
				y = lo * 2.0
				x = hi + y
				if y == x-hi {
					hi = x
				}
			}
			break
		}
	}
	return hi, nil
}

// EncodeBinary64Weights encodes finite weights as canonical big-endian IEEE754 binary64 bytes.
func EncodeBinary64Weights(weights []float64) ([]byte, error) {
	if len(weights) == 0 || len(weights) > 4096 {
		return nil, fmt.Errorf("%w: weights count %d out of bounds", ErrAggregationInvalid, len(weights))
	}
	out := make([]byte, len(weights)*8)
	for i, w := range weights {
		if math.IsNaN(w) || math.IsInf(w, 0) {
			return nil, fmt.Errorf("%w: nonfinite weight", ErrAggregationFailed)
		}
		binary.BigEndian.PutUint64(out[i*8:], math.Float64bits(w))
	}
	return out, nil
}

// DecodeBinary64Weights decodes canonical big-endian IEEE754 binary64 bytes.
func DecodeBinary64Weights(raw []byte, expected uint32) ([]float64, error) {
	if len(raw) == 0 || len(raw)%8 != 0 || uint32(len(raw)/8) != expected {
		return nil, fmt.Errorf("%w: unexpected weights byte length", ErrAggregationCorrupt)
	}
	weights := make([]float64, len(raw)/8)
	for i := range weights {
		v := math.Float64frombits(binary.BigEndian.Uint64(raw[i*8:]))
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("%w: nonfinite weight", ErrAggregationCorrupt)
		}
		weights[i] = v
	}
	return weights, nil
}

// FormatPythonHexFloat encodes finite float64 values using Python float.hex()
// notation so Go and Python produce byte-identical model artifact JSON.
func FormatPythonHexFloat(v float64) (string, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "", fmt.Errorf("%w: cannot format nonfinite float", ErrAggregationFailed)
	}
	bits := math.Float64bits(v)
	sign := ""
	if bits>>63 != 0 {
		sign = "-"
	}
	expBits := int((bits >> 52) & 0x7ff)
	frac := bits & ((uint64(1) << 52) - 1)
	if expBits == 0 {
		if frac == 0 {
			return sign + "0x0.0p+0", nil
		}
		return fmt.Sprintf("%s0x0.%013xp-1022", sign, frac), nil
	}
	return fmt.Sprintf("%s0x1.%013xp%+d", sign, frac, expBits-1023), nil
}

// BuildCandidateArtifact creates a reproducible, byte-deterministic candidate
// artifact from the verified base artifact, round metadata, aggregated weights,
// input digest, and participant count.
func BuildCandidateArtifact(round contracts.FederatedRoundV1, baseManifest contracts.ModelManifestV1, baseArtifact []byte, weights []float64, weightsSHA256, inputSHA256 string, participantCount int, totalSamples uint64) ([]byte, error) {
	if len(baseArtifact) == 0 {
		return nil, fmt.Errorf("%w: empty base artifact", ErrAggregationFailed)
	}
	if sum := sha256.Sum256(baseArtifact); hex.EncodeToString(sum[:]) != round.BaseModelSHA256 || baseManifest.ArtifactSHA256 != round.BaseModelSHA256 {
		return nil, fmt.Errorf("%w: base artifact digest mismatch", ErrAggregationFailed)
	}
	if uint32(len(weights)) != round.ParameterCount {
		return nil, fmt.Errorf("%w: aggregated weight dimension mismatch", ErrAggregationFailed)
	}
	if baseManifest.Architecture == "logistic-baseline.v1" {
		return buildLogisticCandidate(round, baseManifest, baseArtifact, weights)
	}
	hexWeights := make([]string, len(weights))
	for i, w := range weights {
		encoded, err := FormatPythonHexFloat(w)
		if err != nil {
			return nil, err
		}
		hexWeights[i] = encoded
	}
	doc := map[string]any{
		"architecture":       baseManifest.Architecture,
		"base_model_sha256":  round.BaseModelSHA256,
		"base_model_version": round.BaseModelVersion,
		"candidate_id":       round.CandidateID,
		"feature_version":    round.FeatureVersion,
		"input_sha256":       inputSHA256,
		"model_version":      round.CandidateID,
		"parameter_count":    round.ParameterCount,
		"participant_count":  participantCount,
		"round_id":           round.RoundID,
		"schema_version":     GenericCandidateSchemaV1,
		"total_samples":      totalSamples,
		"weighting_policy":   WeightingPolicySampleCountV1,
		"weights":            hexWeights,
		"weights_sha256":     weightsSHA256,
	}
	return encodeCanonicalJSON(doc)
}

func buildLogisticCandidate(round contracts.FederatedRoundV1, baseManifest contracts.ModelManifestV1, baseArtifact []byte, weights []float64) ([]byte, error) {
	if !utf8.Valid(baseArtifact) {
		return nil, fmt.Errorf("%w: base logistic artifact is not valid UTF-8", ErrAggregationFailed)
	}
	dec := json.NewDecoder(bytes.NewReader(baseArtifact))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil || dec.Decode(&struct{}{}) != io.EOF || doc == nil {
		return nil, fmt.Errorf("%w: base logistic artifact is not valid JSON", ErrAggregationFailed)
	}
	if doc["schema_version"] != LogisticBaselineSchemaV1 || doc["architecture"] != baseManifest.Architecture ||
		doc["model_version"] != baseManifest.ModelVersion || doc["feature_version"] != baseManifest.FeatureVersion {
		return nil, fmt.Errorf("%w: base logistic metadata mismatch", ErrAggregationFailed)
	}
	if len(weights) != len(baseManifest.Features)+1 {
		return nil, fmt.Errorf("%w: logistic parameter count mismatch", ErrAggregationFailed)
	}
	interceptHex, err := FormatPythonHexFloat(weights[0])
	if err != nil {
		return nil, err
	}
	weightHexes := make([]string, len(weights)-1)
	for i, w := range weights[1:] {
		encoded, err := FormatPythonHexFloat(w)
		if err != nil {
			return nil, err
		}
		weightHexes[i] = encoded
	}
	doc["model_version"] = round.CandidateID
	doc["intercept"] = interceptHex
	doc["weights"] = weightHexes
	return encodeCanonicalJSON(doc)
}

func encodeCanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalValue(&buf, v); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func writeCanonicalValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		return writeCanonicalString(buf, x)
	case json.Number:
		raw := string(x)
		if raw == "-0" {
			buf.WriteByte('0')
			return nil
		}
		if isCanonicalJSONInteger(raw) {
			buf.WriteString(raw)
			return nil
		}
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("%w: nonfinite or invalid JSON number %q", ErrAggregationFailed, raw)
		}
		buf.WriteString(formatPythonJSONFloat(f))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Errorf("%w: nonfinite float in JSON", ErrAggregationFailed)
		}
		buf.WriteString(formatPythonJSONFloat(x))
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case []string:
		buf.WriteByte('[')
		for i, elem := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalString(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []any:
		buf.WriteByte('[')
		for i, elem := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalValue(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonicalValue(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported JSON value type %T", ErrAggregationFailed, v)
	}
	return nil
}

func writeCanonicalString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: invalid UTF-8 string", ErrAggregationFailed)
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

func isCanonicalJSONInteger(s string) bool {
	if strings.HasPrefix(s, "-") {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	if s == "0" {
		return true
	}
	if s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// formatPythonJSONFloat mirrors CPython float.__repr__ formatting for finite
// IEEE-754 binary64 values so Go and Python serialize identical float tokens.
func formatPythonJSONFloat(f float64) string {
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	expStr := strconv.FormatFloat(f, 'e', -1, 64)
	eIdx := strings.IndexByte(expStr, 'e')
	mant := expStr[:eIdx]
	exp, _ := strconv.Atoi(expStr[eIdx+1:])
	digits := strings.ReplaceAll(mant, ".", "")
	if -4 <= exp && exp < 16 {
		if exp < 0 {
			return sign + "0." + strings.Repeat("0", -exp-1) + digits
		}
		intLen := exp + 1
		if len(digits) <= intLen {
			return sign + digits + strings.Repeat("0", intLen-len(digits)) + ".0"
		}
		return sign + digits[:intLen] + "." + digits[intLen:]
	}
	expSign := "+"
	absExp := exp
	if exp < 0 {
		expSign = "-"
		absExp = -exp
	}
	mantOut := digits[:1]
	if len(digits) > 1 {
		mantOut += "." + digits[1:]
	}
	return fmt.Sprintf("%s%se%s%02d", sign, mantOut, expSign, absExp)
}
