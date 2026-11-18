package main

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const (
	evidenceLogFile     = "signed-evidence.jsonl" // pre-spool service files
	maxSpoolRecordBytes = 400 << 10
	spoolImported       = "spool.imported"
	spoolPending        = "spool.pending"
	spoolRetired        = "spool.acknowledged"
	defaultSpoolRecords = 4096
	maxSpoolRecords     = 65536
)

var errEvidenceFull = errors.New("signed evidence spool full; retained queued records and rejected new evidence")

type spoolRecord struct {
	sequence uint64
	size     int64
}

// The spool lock serializes disk mutations. The caller holds the identity lock so sequences are reserved by one process.
type evidenceSpool struct {
	root           *os.Root
	lock           *os.File
	key            ed25519.PublicKey
	receipt        contracts.EnrollmentAcceptedV1
	queue          []spoolRecord
	acknowledged   uint64
	size, maxBytes int64
	maxRecords     int
	failed         bool
}

func recordName(seq uint64) string { return fmt.Sprintf("spool-%016d.json", seq) }

func spoolSequence(name string) (uint64, bool) {
	value, ok := strings.CutPrefix(name, "spool-")
	if !ok {
		return 0, false
	}
	value, ok = strings.CutSuffix(value, ".json")
	seq, err := strconv.ParseUint(value, 10, 64)
	return seq, ok && err == nil && name == recordName(seq)
}

func openEvidenceSpool(dir string, maxBytes int64, maxRecords int, key ed25519.PublicKey, receipt contracts.EnrollmentAcceptedV1) (*evidenceSpool, error) {
	if maxRecords == 0 {
		maxRecords = defaultSpoolRecords
	}
	if err := validateSpoolDirectory(dir); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.New("open evidence spool directory")
	}
	s := &evidenceSpool{root: root, key: key, receipt: receipt, maxBytes: maxBytes, maxRecords: maxRecords}
	s.lock, err = s.acquire()
	if err != nil {
		root.Close()
		return nil, err
	}
	if err := s.recover(); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *evidenceSpool) close() {
	s.lock.Close()
	s.root.Close()
}

func (s *evidenceSpool) acquire() (*os.File, error) {
	const name = "spool.lock"
	if info, err := s.root.Lstat(name); (err == nil && !info.Mode().IsRegular()) || (err != nil && !errors.Is(err, os.ErrNotExist)) {
		return nil, errors.New("unsafe evidence spool lock")
	}
	file, err := s.root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("open evidence spool lock")
	}
	if validateSpoolFile(file) != nil || lockSpoolFile(file) != nil {
		file.Close()
		return nil, errors.New("unsafe or already locked evidence spool")
	}
	return file, nil
}

func (s *evidenceSpool) recover() error {
	if _, envelope, err := s.read(spoolRetired); err == nil {
		s.acknowledged = envelope.Sequence
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("corrupt acknowledged spool record")
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return errors.New("list evidence spool")
	}
	defer dir.Close()
	for {
		names, err := dir.Readdirnames(128)
		for _, name := range names {
			if !strings.HasPrefix(strings.ToLower(name), "spool-") {
				continue
			}
			seq, ok := spoolSequence(name)
			data, envelope, readErr := s.read(name)
			if !ok || readErr != nil || envelope.Sequence != seq || seq <= s.acknowledged {
				return fmt.Errorf("corrupt or out-of-order evidence spool record at sequence %d", seq)
			}
			s.size += int64(len(data))
			s.queue = append(s.queue, spoolRecord{seq, int64(len(data))})
			if len(s.queue) > maxSpoolRecords || s.size > maxEvidenceCap {
				return errors.New("spool exceeds supported recovery bounds")
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("list evidence spool records")
		}
	}
	slices.SortFunc(s.queue, func(a, b spoolRecord) int {
		return cmp.Compare(a.sequence, b.sequence)
	})
	if err := s.removeRecoverable(spoolPending); err != nil {
		return err
	}
	if err := s.importLegacy(); err != nil {
		return err
	}
	return s.removeRecoverable(spoolImported)
}

func (s *evidenceSpool) openRegular(name string) (*os.File, error) {
	info, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("spool record is not a regular file")
	}
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	got, err := f.Stat()
	if err != nil || !os.SameFile(info, got) || validateSpoolFile(f) != nil {
		f.Close()
		return nil, errors.New("unsafe spool record")
	}
	return f, nil
}

func (s *evidenceSpool) verify(data []byte) (contracts.EvidenceEnvelopeV1, error) {
	var e contracts.EvidenceEnvelopeV1
	if json.Unmarshal(data, &e) != nil || e.VerifySignature(s.key) != nil ||
		e.DeviceID != s.receipt.DeviceID || e.DeploymentID != s.receipt.DeploymentID || e.SigningKeyID != s.receipt.SigningKeyID {
		return e, errors.New("invalid signed spool record")
	}
	return e, nil
}

func (s *evidenceSpool) read(name string) ([]byte, contracts.EvidenceEnvelopeV1, error) {
	f, err := s.openRegular(name)
	if err != nil {
		return nil, contracts.EvidenceEnvelopeV1{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSpoolRecordBytes+1))
	if err != nil || len(data) > maxSpoolRecordBytes {
		return nil, contracts.EvidenceEnvelopeV1{}, errors.New("read bounded spool record")
	}
	e, err := s.verify(data)
	return data, e, err
}

// Migration preserves the entire legacy line as stored. A partial migration
// resumes by comparing already committed copies byte for byte.
func (s *evidenceSpool) importLegacy() error {
	f, err := s.openRegular(evidenceLogFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("open legacy evidence for migration")
	}
	defer f.Close()
	reader := bufio.NewReaderSize(f, maxSpoolRecordBytes+1)
	last := uint64(0)
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) && len(line) == 0 {
			break
		}
		if err != nil || len(line) > maxSpoolRecordBytes {
			return errors.New("legacy evidence contains an incomplete or oversized record; preserve for recovery")
		}
		e, err := s.verify(line)
		if err != nil || e.Sequence <= last || e.Sequence <= s.acknowledged {
			return errors.New("legacy evidence contains a corrupt or out-of-order record")
		}
		last = e.Sequence
		if existing, _, err := s.read(recordName(last)); err == nil {
			if !bytes.Equal(existing, line) {
				return errors.New("legacy evidence differs from previously migrated bytes")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("inspect migrated evidence")
		} else if len(s.queue) >= maxSpoolRecords || int64(len(line)) > maxEvidenceCap-s.size {
			return errors.New("legacy evidence exceeds spool recovery bounds; preserve for recovery")
		} else if err := s.commitRecord(line, last); err != nil {
			return fmt.Errorf("import legacy evidence: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return errors.New("close legacy evidence before migration commit")
	}
	// Rename the source out of the active namespace before any dequeue.
	if err := commitSpoolRename(s.root, evidenceLogFile, spoolImported); err != nil {
		return errors.New("commit legacy evidence migration")
	}
	return nil
}

func (s *evidenceSpool) removeRecoverable(name string) error {
	info, err := s.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || s.root.Remove(name) != nil {
		return errors.New("unsafe spool staging file")
	}
	return nil
}

func (s *evidenceSpool) lastSequence() uint64 {
	if len(s.queue) == 0 {
		return s.acknowledged
	}
	return s.queue[len(s.queue)-1].sequence
}

func (s *evidenceSpool) append(envelope contracts.EvidenceEnvelopeV1) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return errors.New("encode spool record")
	}
	if _, err := s.verify(data); err != nil {
		return err
	}
	return s.appendBytes(append(data, '\n'), envelope.Sequence)
}

func (s *evidenceSpool) appendBytes(data []byte, seq uint64) error {
	if len(data) > maxSpoolRecordBytes {
		return errors.New("signed envelope exceeds spool record bound")
	}
	if len(s.queue) >= s.maxRecords || int64(len(data)) > s.maxBytes-s.size {
		return errEvidenceFull
	}
	return s.commitRecord(data, seq)
}

func (s *evidenceSpool) commitRecord(data []byte, seq uint64) error {
	if s.failed || seq <= s.lastSequence() {
		return errors.New("spool unavailable or sequence did not increase")
	}
	s.failed = true // an uncertain write requires recovery before further mutations
	file, err := s.root.OpenFile(spoolPending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("stage spool record")
	}
	writeErr := validateSpoolFile(file)
	if writeErr == nil {
		_, writeErr = file.Write(data)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("flush staged spool record")
	}
	spoolStage("append-staged")
	if err := commitSpoolRename(s.root, spoolPending, recordName(seq)); err != nil {
		return errors.New("commit spool record")
	}
	spoolStage("append-committed")
	s.queue = append(s.queue, spoolRecord{seq, int64(len(data))})
	s.size += int64(len(data))
	s.failed = false
	return nil
}

var spoolStage = func(string) {}

func (s *evidenceSpool) head() ([]byte, contracts.EvidenceEnvelopeV1, error) {
	if s.failed {
		return nil, contracts.EvidenceEnvelopeV1{}, errors.New("spool needs recovery")
	}
	if len(s.queue) == 0 {
		return nil, contracts.EvidenceEnvelopeV1{}, io.EOF
	}
	head := s.queue[0]
	data, envelope, err := s.read(recordName(head.sequence))
	if err != nil || envelope.Sequence != head.sequence || int64(len(data)) != head.size {
		return nil, contracts.EvidenceEnvelopeV1{}, fmt.Errorf("corrupt spool head at sequence %d", head.sequence)
	}
	return data, envelope, nil
}

func (s *evidenceSpool) acknowledge(key ed25519.PublicKey, ack contracts.AcknowledgementV1) error {
	_, envelope, err := s.head()
	if err != nil {
		return err
	}
	if ack.Status != "accepted" || ack.VerifyForEvidence(key, envelope) != nil {
		return errors.New("a verified accepted acknowledgement for the spool head is required")
	}
	s.failed = true
	spoolStage("dequeue-staged")
	// This move both retires the record and advances the durable high-water
	// mark. Recovery sees either the intact head or the intact retired record.
	if err := commitSpoolRename(s.root, recordName(envelope.Sequence), spoolRetired); err != nil {
		return errors.New("commit spool acknowledgement")
	}
	spoolStage("dequeue-committed")
	s.acknowledged = envelope.Sequence
	s.size -= s.queue[0].size
	s.queue = s.queue[1:]
	s.failed = false
	return nil
}
