package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

/*
FILv5.2 Userland Pagefile Bands (demo)

What’s new vs v1:
1) N strips (pagefile “bands”), not just 2.
2) Strip index stored in the global header region (1MiB reserved):
   - Per-strip offsets, sizes, and integrity fields.
3) Merkle-ish verification:
   - Each strip builds a Merkle root over transition records written in the transitions subregion.
   - Root is stored BOTH in:
     a) strip index entry (global index)
     b) headroom routing metadata subregion
4) Headroom split into 3 subregions:
   (a) transitions      : append-only transition records (HITC-ish)
   (b) routing metadata : parameters + per-cycle summary + Merkle root
   (c) recovery hints   : sparse checkpoints (hashes + offsets) to aid reconstruction

Reconstructable (toy):
- Transition record format includes:
  - strip, logicalCell, physCell
  - prevDigest (16 bytes) + currDigest (16 bytes)  (a simple hash-chain)
  - packed delta bytes
- With the routing metadata + chain, you can replay/verify ordering and detect corruption.
- Recovery hints provide checkpoints of hashed states and file offsets for faster audit.

NOT cryptography. NOT production. Educational substrate.
*/

const (
	globalMagic = "FILPF52" // FIL PageFile v5.2 (demo)
	stripMagic  = "STRP"
	versionU32  = 0x00050200
)

// -------- Zipkin/Jaeger (no deps) tracing --------

type zipkinEndpoint struct {
	ServiceName string `json:"serviceName"`
}

type zipkinSpan struct {
	TraceID       string            `json:"traceId"`
	ID            string            `json:"id"`
	ParentID      string            `json:"parentId,omitempty"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind,omitempty"`
	TsMicros      int64             `json:"timestamp"`
	DurMicros     int64             `json:"duration"`
	LocalEndpoint zipkinEndpoint    `json:"localEndpoint"`
	Tags          map[string]string `json:"tags,omitempty"`
}

type spanKey struct{}

type tracer struct {
	mu      sync.Mutex
	service string
	traceID string
	spans   []zipkinSpan
}

func newTracer(service string) *tracer { return &tracer{service: service, traceID: newTraceID()} }

func newTraceID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
func newSpanID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type spanHandle struct {
	tr     *tracer
	id     string
	parent string
	name   string
	start  time.Time
	tags   map[string]string
}

func (t *tracer) Start(ctx context.Context, name string, tags map[string]string) (context.Context, *spanHandle) {
	parent := ""
	if v := ctx.Value(spanKey{}); v != nil {
		if s, ok := v.(string); ok {
			parent = s
		}
	}
	h := &spanHandle{tr: t, id: newSpanID(), parent: parent, name: name, start: time.Now(), tags: tags}
	ctx = context.WithValue(ctx, spanKey{}, h.id)
	return ctx, h
}

func (h *spanHandle) End() {
	d := time.Since(h.start)
	s := zipkinSpan{
		TraceID:       h.tr.traceID,
		ID:            h.id,
		ParentID:      h.parent,
		Name:          h.name,
		TsMicros:      h.start.UnixMicro(),
		DurMicros:     d.Microseconds(),
		LocalEndpoint: zipkinEndpoint{ServiceName: h.tr.service},
		Tags:          h.tags,
	}
	h.tr.mu.Lock()
	h.tr.spans = append(h.tr.spans, s)
	h.tr.mu.Unlock()
}

func (t *tracer) Flush(ctx context.Context, zipkinURL, fallbackPath string) error {
	t.mu.Lock()
	payload := append([]zipkinSpan(nil), t.spans...)
	t.mu.Unlock()
	if len(payload) == 0 {
		return nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if zipkinURL != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, zipkinURL, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				log.Printf("trace.flush ok url=%s spans=%d", zipkinURL, len(payload))
				return nil
			}
			err = fmt.Errorf("zipkin endpoint status=%s", resp.Status)
		}
		log.Printf("trace.flush failed url=%s err=%v (writing fallback)", zipkinURL, err)
	}
	if fallbackPath == "" {
		fallbackPath = "trace_spans.json"
	}
	if err := os.WriteFile(fallbackPath, b, 0644); err != nil {
		return err
	}
	log.Printf("trace.flush wrote file=%s spans=%d", fallbackPath, len(payload))
	return nil
}

// -------- Layout + Index --------

type globalHeader struct {
	Magic       [8]byte
	Version     uint32
	HeaderBytes uint32
	CreatedUnix int64

	StripBytes  uint64
	NumStrips   uint32
	CellBytes   uint32
	HeadroomPct float32

	IndexOffset uint64 // offset from file start
	IndexBytes  uint64 // bytes reserved for index entries

	Reserved [48]byte
	CRC32    uint32
}

type stripHeader struct {
	Magic       [4]byte
	StripIndex  uint32
	HeaderBytes uint32
	CellBytes   uint32
	NumCells    uint64

	CellRegionOffset uint64
	CellRegionBytes  uint64

	HeadroomOffset uint64
	HeadroomBytes  uint64

	// Headroom split
	TransitionsOffset uint64
	TransitionsBytes  uint64
	RoutingOffset     uint64
	RoutingBytes      uint64
	RecoveryOffset    uint64
	RecoveryBytes     uint64

	MobiusEnabled uint8
	Reserved      [31]byte
	CRC32         uint32
}

type stripIndexEntry struct {
	StripIndex uint32
	Flags      uint32

	StripBase       uint64
	StripBytes      uint64
	StripHeaderOff  uint64
	CellRegionOff   uint64
	CellRegionBytes uint64

	TransitionsOff  uint64
	TransitionsBytes uint64
	RoutingOff      uint64
	RoutingBytes    uint64
	RecoveryOff     uint64
	RecoveryBytes   uint64

	// Integrity
	TransitionsMerkleRoot [32]byte
	RoutingCRC32          uint32
	RecoveryCRC32         uint32
	IndexCRC32            uint32
}

type layout struct {
	stripBytes       uint64
	cellBytes        uint32
	headroomPct      float64
	headerBytes      uint64
	stripHeaderBytes uint64

	cellRegionBytes uint64
	headroomBytes   uint64
	numCells        uint64

	// headroom split ratios
	transitionsPct float64
	routingPct     float64
	recoveryPct    float64
}

func computeLayout(stripBytes uint64, cellBytes uint32, headroomPct float64, tPct, rPct, hPct float64) (layout, error) {
	if stripBytes < 1<<20 {
		return layout{}, fmt.Errorf("stripBytes too small: %d", stripBytes)
	}
	if cellBytes < 256 || cellBytes&(cellBytes-1) != 0 {
		return layout{}, fmt.Errorf("cellBytes must be power of two >= 256, got %d", cellBytes)
	}
	if headroomPct < 0.0 || headroomPct > 30.0 {
		return layout{}, fmt.Errorf("headroomPct must be 0..30, got %.2f", headroomPct)
	}
	if tPct <= 0 || rPct <= 0 || hPct <= 0 {
		return layout{}, fmt.Errorf("headroom split pcts must be >0, got t=%.2f r=%.2f h=%.2f", tPct, rPct, hPct)
	}
	s := tPct + rPct + hPct
	tPct, rPct, hPct = tPct/s, rPct/s, hPct/s

	const globalHeaderBytes = 1 << 20 // 1MiB reserved region (header + index)
	const stripHeaderBytes = 64 << 10 // 64KiB per strip

	hr := uint64(float64(stripBytes) * (headroomPct / 100.0))
	if hr < (1 << 16) {
		hr = 1 << 16
	}
	usable := stripBytes - stripHeaderBytes
	if usable <= hr {
		return layout{}, fmt.Errorf("stripBytes too small after headers/headroom: strip=%d header=%d headroom=%d", stripBytes, stripHeaderBytes, hr)
	}
	cellRegion := usable - hr
	numCells := cellRegion / uint64(cellBytes)
	cellRegion = numCells * uint64(cellBytes)

	return layout{
		stripBytes:       stripBytes,
		cellBytes:        cellBytes,
		headroomPct:      headroomPct,
		headerBytes:      globalHeaderBytes,
		stripHeaderBytes: stripHeaderBytes,
		cellRegionBytes:  cellRegion,
		headroomBytes:    hr,
		numCells:         numCells,
		transitionsPct:   tPct,
		routingPct:       rPct,
		recoveryPct:      hPct,
	}, nil
}

func fileOffsetForStrip(globalHeaderBytes uint64, stripBytes uint64, stripIndex uint32) uint64 {
	return globalHeaderBytes + uint64(stripIndex)*stripBytes
}

// Möbius addressing (twist each lap)
func mobiusPhysicalIndex(i, n uint64) uint64 {
	if n == 0 {
		return 0
	}
	lap := i / n
	pos := i % n
	if lap%2 == 0 {
		return pos
	}
	return (n - 1) - pos
}

func sha256Trunc16(b []byte) [16]byte {
	h := sha256.Sum256(b)
	var out [16]byte
	copy(out[:], h[:16])
	return out
}

func merkleRoot(leaves [][]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256(nil)
	}
	level := make([][32]byte, 0, len(leaves))
	for _, l := range leaves {
		level = append(level, sha256.Sum256(l))
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				// duplicate last
				x := append(level[i][:], level[i][:]...)
				next = append(next, sha256.Sum256(x))
			} else {
				x := append(level[i][:], level[i+1][:]...)
				next = append(next, sha256.Sum256(x))
			}
		}
		level = next
	}
	return level[0]
}

func initContainer(ctx context.Context, tr *tracer, path string, lay layout, numStrips uint32) error {
	ctx, sp := tr.Start(ctx, "container.init", map[string]string{
		"path":        path,
		"stripBytes":  fmt.Sprint(lay.stripBytes),
		"cellBytes":   fmt.Sprint(lay.cellBytes),
		"headroomPct": fmt.Sprintf("%.2f", lay.headroomPct),
		"numStrips":   fmt.Sprint(numStrips),
	})
	defer sp.End()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	totalSize := int64(lay.headerBytes) + int64(numStrips)*int64(lay.stripBytes)
	if err := f.Truncate(totalSize); err != nil {
		return err
	}

	// Index placement inside the 1MiB reserved header region:
	// [globalHeader][stripIndexEntries...][padding]
	ghSize := uint64(binary.Size(globalHeader{}))
	entrySize := uint64(binary.Size(stripIndexEntry{}))
	indexOff := ghSize
	indexBytes := entrySize * uint64(numStrips)
	if indexOff+indexBytes > lay.headerBytes {
		return fmt.Errorf("index does not fit in header region: need=%d have=%d (numStrips too large)", indexOff+indexBytes, lay.headerBytes)
	}

	var gh globalHeader
	copy(gh.Magic[:], []byte(globalMagic))
	gh.Version = versionU32
	gh.HeaderBytes = uint32(lay.headerBytes)
	gh.CreatedUnix = time.Now().Unix()
	gh.StripBytes = lay.stripBytes
	gh.NumStrips = numStrips
	gh.CellBytes = lay.cellBytes
	gh.HeadroomPct = float32(lay.headroomPct)
	gh.IndexOffset = indexOff
	gh.IndexBytes = indexBytes

	// Write strip headers + build index entries
	entries := make([]stripIndexEntry, 0, numStrips)

	for s := uint32(0); s < numStrips; s++ {
		stripBase := fileOffsetForStrip(lay.headerBytes, lay.stripBytes, s)
		cellBase := stripBase + lay.stripHeaderBytes
		headBase := cellBase + lay.cellRegionBytes

		// Split headroom
		tBytes := uint64(float64(lay.headroomBytes) * lay.transitionsPct)
		rBytes := uint64(float64(lay.headroomBytes) * lay.routingPct)
		hBytes := lay.headroomBytes - tBytes - rBytes

		tOff := headBase
		rOff := tOff + tBytes
		hOff := rOff + rBytes

		var sh stripHeader
		copy(sh.Magic[:], []byte(stripMagic))
		sh.StripIndex = s
		sh.HeaderBytes = uint32(lay.stripHeaderBytes)
		sh.CellBytes = lay.cellBytes
		sh.NumCells = lay.numCells
		sh.CellRegionOffset = cellBase
		sh.CellRegionBytes = lay.cellRegionBytes
		sh.HeadroomOffset = headBase
		sh.HeadroomBytes = lay.headroomBytes

		sh.TransitionsOffset = tOff
		sh.TransitionsBytes = tBytes
		sh.RoutingOffset = rOff
		sh.RoutingBytes = rBytes
		sh.RecoveryOffset = hOff
		sh.RecoveryBytes = hBytes
		sh.MobiusEnabled = 1

		sh.CRC32 = 0
		sb := new(bytes.Buffer)
		_ = binary.Write(sb, binary.LittleEndian, &sh)
		sraw := sb.Bytes()
		sh.CRC32 = crc32.ChecksumIEEE(sraw[:len(sraw)-4])
		sb.Reset()
		_ = binary.Write(sb, binary.LittleEndian, &sh)

		if _, err := f.WriteAt(sb.Bytes(), int64(stripBase)); err != nil {
			return err
		}

		var ent stripIndexEntry
		ent.StripIndex = s
		ent.Flags = 1 // mobius enabled (toy)
		ent.StripBase = stripBase
		ent.StripBytes = lay.stripBytes
		ent.StripHeaderOff = stripBase
		ent.CellRegionOff = cellBase
		ent.CellRegionBytes = lay.cellRegionBytes
		ent.TransitionsOff = tOff
		ent.TransitionsBytes = tBytes
		ent.RoutingOff = rOff
		ent.RoutingBytes = rBytes
		ent.RecoveryOff = hOff
		ent.RecoveryBytes = hBytes
		// roots/CRCs filled later after writes
		entries = append(entries, ent)
	}

	// Write global header with CRC
	gh.CRC32 = 0
	gb := new(bytes.Buffer)
	_ = binary.Write(gb, binary.LittleEndian, &gh)
	graw := gb.Bytes()
	gh.CRC32 = crc32.ChecksumIEEE(graw[:len(graw)-4])
	gb.Reset()
	_ = binary.Write(gb, binary.LittleEndian, &gh)
	if _, err := f.WriteAt(gb.Bytes(), 0); err != nil {
		return err
	}

	// Write initial index (blank roots/CRCs)
	if err := writeStripIndex(ctx, tr, f, gh, entries); err != nil {
		return err
	}

	log.Printf("container.init ok path=%s total=%d bytes strips=%d cells/strip=%d indexBytes=%d",
		path, totalSize, numStrips, lay.numCells, indexBytes)
	return nil
}

func writeStripIndex(ctx context.Context, tr *tracer, f *os.File, gh globalHeader, entries []stripIndexEntry) error {
	ctx, sp := tr.Start(ctx, "index.write", map[string]string{"entries": fmt.Sprint(len(entries))})
	defer sp.End()

	// Ensure deterministic order
	sort.Slice(entries, func(i, j int) bool { return entries[i].StripIndex < entries[j].StripIndex })

	entrySize := int64(binary.Size(stripIndexEntry{}))
	base := int64(gh.IndexOffset)

	for i := range entries {
		entries[i].IndexCRC32 = 0
		var b bytes.Buffer
		_ = binary.Write(&b, binary.LittleEndian, &entries[i])
		raw := b.Bytes()
		entries[i].IndexCRC32 = crc32.ChecksumIEEE(raw[:len(raw)-4])

		b.Reset()
		_ = binary.Write(&b, binary.LittleEndian, &entries[i])
		if _, err := f.WriteAt(b.Bytes(), base+int64(i)*entrySize); err != nil {
			return err
		}
	}
	return nil
}

func readGlobalHeader(f *os.File) (globalHeader, error) {
	var gh globalHeader
	b := make([]byte, binary.Size(globalHeader{}))
	if _, err := f.ReadAt(b, 0); err != nil {
		return gh, err
	}
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &gh); err != nil {
		return gh, err
	}
	if string(gh.Magic[:7]) != globalMagic[:7] {
		return gh, fmt.Errorf("bad magic: %q", string(gh.Magic[:]))
	}
	// CRC check (best-effort)
	tmp := gh
	tmp.CRC32 = 0
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, &tmp)
	raw := buf.Bytes()
	want := crc32.ChecksumIEEE(raw[:len(raw)-4])
	if want != gh.CRC32 {
		return gh, fmt.Errorf("global header CRC mismatch: got=%08x want=%08x", gh.CRC32, want)
	}
	return gh, nil
}

func readStripIndex(f *os.File, gh globalHeader) ([]stripIndexEntry, error) {
	entrySize := int64(binary.Size(stripIndexEntry{}))
	n := int(gh.NumStrips)
	out := make([]stripIndexEntry, 0, n)
	base := int64(gh.IndexOffset)
	for i := 0; i < n; i++ {
		b := make([]byte, entrySize)
		if _, err := f.ReadAt(b, base+int64(i)*entrySize); err != nil {
			return nil, err
		}
		var e stripIndexEntry
		if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &e); err != nil {
			return nil, err
		}
		// verify entry CRC
		tmp := e
		tmp.IndexCRC32 = 0
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.LittleEndian, &tmp)
		raw := buf.Bytes()
		want := crc32.ChecksumIEEE(raw[:len(raw)-4])
		if want != e.IndexCRC32 {
			return nil, fmt.Errorf("index entry %d CRC mismatch: got=%08x want=%08x", i, e.IndexCRC32, want)
		}
		out = append(out, e)
	}
	return out, nil
}

// -------- transition + routing + recovery formats --------

// Routing metadata (small JSON blob stored at start of routing region)
type routingMeta struct {
	Version        string `json:"version"`
	CreatedUnix    int64  `json:"created_unix"`
	CycleIndex     int    `json:"cycle_index"`
	NumHops        int    `json:"num_hops"`
	CellBytes      int    `json:"cell_bytes"`
	NumCells       uint64 `json:"num_cells"`
	Mobius         bool   `json:"mobius"`
	SeedTag        string `json:"seed_tag"`
	TransitionsRoot string `json:"transitions_merkle_root_hex"`
	TransitionsBytes int   `json:"transitions_bytes"`
	AvgResidual    float64 `json:"avg_residual"`
	PackedVsRaw    float64 `json:"packed_vs_raw"`
}

// Recovery hint entry (binary)
type recoveryHint struct {
	LogicalCell uint64
	PhysCell    uint64
	FileOffset  uint64
	StateHash   [16]byte
}

// -------- Runner --------

type runner struct {
	tr           *tracer
	path         string
	outB64Chars  int
	deflateLevel int
	numHops      int
	f            *os.File

	gh     globalHeader
	index  []stripIndexEntry
	cellBytes uint32
	numCells  uint64
}

func (r *runner) open() error {
	f, err := os.OpenFile(r.path, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	r.f = f
	gh, err := readGlobalHeader(f)
	if err != nil {
		return err
	}
	idx, err := readStripIndex(f, gh)
	if err != nil {
		return err
	}
	r.gh = gh
	r.index = idx
	r.cellBytes = gh.CellBytes
	// derive numCells from first entry
	if len(idx) > 0 {
		r.numCells = idx[0].CellRegionBytes / uint64(r.cellBytes)
	}
	return nil
}
func (r *runner) close() { if r.f != nil { r.f.Close() } }

func (r *runner) stripForHop(hop int) stripIndexEntry {
	return r.index[hop%len(r.index)]
}

func xorDelta(prev, curr []byte) []byte {
	out := make([]byte, len(curr))
	if len(prev) < len(curr) {
		copy(out, curr)
		for i := 0; i < len(prev); i++ {
			out[i] = prev[i] ^ curr[i]
		}
		return out
	}
	for i := 0; i < len(curr); i++ {
		out[i] = prev[i] ^ curr[i]
	}
	return out
}

func deflateCompress(in []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, level)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(in); err != nil {
		w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func fixedSizeB64(data []byte, outChars int) string {
	if outChars <= 0 {
		return base64.StdEncoding.EncodeToString(data)
	}
	enc := base64.StdEncoding.EncodeToString(data)
	if len(enc) == outChars {
		return enc
	}
	if len(enc) > outChars {
		return enc[:outChars]
	}
	pad := bytes.Repeat([]byte("A"), outChars-len(enc))
	return enc + string(pad)
}

func byteEnergy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var sum uint64
	for _, x := range b {
		sum += uint64(x)
	}
	return float64(sum) / float64(len(b))
}

func abs(x float64) float64 { if x < 0 { return -x }; return x }
func min(a, b int) int      { if a < b { return a }; return b }
func max(a, b int) int      { if a > b { return a }; return b }

func mutateInPlace(b []byte, hop uint32, cycle uint32) {
	shift := int((hop + cycle) % uint32(max(1, len(b))))
	if shift > 0 {
		tmp := append([]byte(nil), b...)
		copy(b, tmp[shift:])
		copy(b[len(b)-shift:], tmp[:shift])
	}
	mask := byte((hop*131 + cycle*17) & 0xFF)
	for i := range b {
		x := b[i] ^ mask
		b[i] = (x & 0xF0) | ((x >> 4) & 0x0F)
	}
}

type cycleResult struct {
	rawBytes     int
	packedBytes  int
	residuals    []float64
	envelopeB64  string
	perStripRoot map[uint32][32]byte
}

func (r *runner) writeCellAndTransition(ctx context.Context, ent stripIndexEntry, logicalCell uint64, data []byte, transitionBuf *bytes.Buffer, prevDigest [16]byte, leaves *[][]byte) (raw int, packed int, residual float64, newDigest [16]byte, err error) {
	ctx, sp := r.tr.Start(ctx, "cell.write", map[string]string{
		"strip":       fmt.Sprint(ent.StripIndex),
		"logicalCell": fmt.Sprint(logicalCell),
	})
	defer sp.End()

	phys := mobiusPhysicalIndex(logicalCell, r.numCells)
	fileOff := int64(ent.CellRegionOff + phys*uint64(r.cellBytes))

	prev := make([]byte, r.cellBytes)
	_, _ = r.f.ReadAt(prev, fileOff)

	if _, err := r.f.WriteAt(data, fileOff); err != nil {
		sp.tags = map[string]string{"err": err.Error()}
		return 0, 0, 0, prevDigest, err
	}

	delta := xorDelta(prev, data)
	packedBytes, err := deflateCompress(delta, r.deflateLevel)
	if err != nil {
		return 0, 0, 0, prevDigest, err
	}

	ePrev := byteEnergy(prev)
	eCurr := byteEnergy(data)
	res := abs(eCurr - ePrev)

	// Transition record:
	// [strip u32][logical u64][phys u64][packedLen u32][prevDigest16][currDigest16][packed...]
	// digest = sha256(prevDigest||strip||logical||phys||packed)
	var recHdr bytes.Buffer
	_ = binary.Write(&recHdr, binary.LittleEndian, ent.StripIndex)
	_ = binary.Write(&recHdr, binary.LittleEndian, logicalCell)
	_ = binary.Write(&recHdr, binary.LittleEndian, phys)
	_ = binary.Write(&recHdr, binary.LittleEndian, uint32(len(packedBytes)))
	recHdr.Write(prevDigest[:])
	tmp := append(recHdr.Bytes(), packedBytes...)
	d := sha256Trunc16(tmp)
	recHdr.Write(d[:])

	transitionBuf.Write(recHdr.Bytes())
	transitionBuf.Write(packedBytes)

	// Leaf for merkle: digest32 of [prevDigest16||currDigest16||crc32(packed)]
	cr := crc32.ChecksumIEEE(packedBytes)
	leaf := make([]byte, 0, 16+16+4)
	leaf = append(leaf, prevDigest[:]...)
	leaf = append(leaf, d[:]...)
	var crb [4]byte
	binary.LittleEndian.PutUint32(crb[:], cr)
	leaf = append(leaf, crb[:]...)
	*leaves = append(*leaves, leaf)

	sp.tags = map[string]string{
		"physCell":     fmt.Sprint(phys),
		"packedBytes":  fmt.Sprint(len(packedBytes)),
		"residual":     fmt.Sprintf("%.6f", res),
	}
	return len(data), len(packedBytes), res, d, nil
}

func (r *runner) flushTransitions(ctx context.Context, ent stripIndexEntry, buf *bytes.Buffer) ([]byte, error) {
	ctx, sp := r.tr.Start(ctx, "transitions.flush", map[string]string{
		"strip": fmt.Sprint(ent.StripIndex),
		"bytes": fmt.Sprint(buf.Len()),
	})
	defer sp.End()

	maxBytes := int(ent.TransitionsBytes)
	out := buf.Bytes()
	if len(out) > maxBytes {
		// keep tail (newest)
		out = out[len(out)-maxBytes:]
	}
	if _, err := r.f.WriteAt(out, int64(ent.TransitionsOff)); err != nil {
		sp.tags = map[string]string{"err": err.Error()}
		return nil, err
	}
	return out, nil
}

func (r *runner) writeRoutingMeta(ctx context.Context, ent stripIndexEntry, meta routingMeta) (uint32, error) {
	ctx, sp := r.tr.Start(ctx, "routing.write", map[string]string{"strip": fmt.Sprint(ent.StripIndex)})
	defer sp.End()

	b, err := json.Marshal(meta)
	if err != nil {
		return 0, err
	}
	if len(b) > int(ent.RoutingBytes) {
		b = b[:ent.RoutingBytes]
	}
	if _, err := r.f.WriteAt(b, int64(ent.RoutingOff)); err != nil {
		sp.tags = map[string]string{"err": err.Error()}
		return 0, err
	}
	return crc32.ChecksumIEEE(b), nil
}

func (r *runner) writeRecoveryHints(ctx context.Context, ent stripIndexEntry, hints []recoveryHint) (uint32, error) {
	ctx, sp := r.tr.Start(ctx, "recovery.write", map[string]string{"strip": fmt.Sprint(ent.StripIndex), "count": fmt.Sprint(len(hints))})
	defer sp.End()

	var buf bytes.Buffer
	for _, h := range hints {
		_ = binary.Write(&buf, binary.LittleEndian, &h)
	}
	b := buf.Bytes()
	if len(b) > int(ent.RecoveryBytes) {
		// keep tail
		b = b[len(b)-int(ent.RecoveryBytes):]
	}
	if _, err := r.f.WriteAt(b, int64(ent.RecoveryOff)); err != nil {
		sp.tags = map[string]string{"err": err.Error()}
		return 0, err
	}
	return crc32.ChecksumIEEE(b), nil
}

func (r *runner) runCycle(ctx context.Context, batch []byte, cycleIndex int, seedTag string) (*cycleResult, error) {
	ctx, sp := r.tr.Start(ctx, "cycle.run", map[string]string{
		"cycle":      fmt.Sprint(cycleIndex),
		"batchBytes": fmt.Sprint(len(batch)),
	})
	defer sp.End()

	if len(batch) == 0 {
		return nil, errors.New("empty batch")
	}

	cells := len(batch) / int(r.cellBytes)
	if len(batch)%int(r.cellBytes) != 0 {
		cells++
	}

	// Per strip buffers + merkle leaves + recovery hints
	transBuf := make(map[uint32]*bytes.Buffer)
	leaves := make(map[uint32][][]byte)
	hints := make(map[uint32][]recoveryHint)

	for _, ent := range r.index {
		transBuf[ent.StripIndex] = new(bytes.Buffer)
		leaves[ent.StripIndex] = make([][]byte, 0, 1024)
		hints[ent.StripIndex] = make([]recoveryHint, 0, 128)
	}

	// per strip hash-chain state
	prevDigest := make(map[uint32][16]byte)
	for _, ent := range r.index {
		prevDigest[ent.StripIndex] = sha256Trunc16([]byte(fmt.Sprintf("strip-%d-seed-%s", ent.StripIndex, seedTag)))
	}

	res := &cycleResult{
		residuals:    make([]float64, 0, r.numHops*cells),
		perStripRoot: make(map[uint32][32]byte),
	}

	// write path: hop -> strip -> cells
	for hop := 0; hop < r.numHops; hop++ {
		ent := r.stripForHop(hop)
		sb := transBuf[ent.StripIndex]
		pd := prevDigest[ent.StripIndex]
		lv := leaves[ent.StripIndex]

		for c := 0; c < cells; c++ {
			cellData := make([]byte, r.cellBytes)
			copy(cellData, batch[c*int(r.cellBytes):min(len(batch), (c+1)*int(r.cellBytes))])

			mutateInPlace(cellData, uint32(hop), uint32(cycleIndex))

			logical := uint64(hop)*r.numCells + uint64(c)
			raw, packed, resid, nd, err := r.writeCellAndTransition(ctx, ent, logical, cellData, sb, pd, &lv)
			if err != nil {
				sp.tags = map[string]string{"err": err.Error()}
				return nil, err
			}
			pd = nd
			res.rawBytes += raw
			res.packedBytes += packed
			res.residuals = append(res.residuals, resid)

			// Sparse recovery hints: every 1024 transitions per strip
			if (sb.Len() > 0) && ((len(lv) % 1024) == 0) {
				phys := mobiusPhysicalIndex(logical, r.numCells)
				fileOff := ent.CellRegionOff + phys*uint64(r.cellBytes)
				h := recoveryHint{
					LogicalCell: logical,
					PhysCell:    phys,
					FileOffset:  fileOff,
					StateHash:   sha256Trunc16(cellData),
				}
				hints[ent.StripIndex] = append(hints[ent.StripIndex], h)
			}
		}
		prevDigest[ent.StripIndex] = pd
		leaves[ent.StripIndex] = lv
	}

	// Flush per-strip transitions + compute merkle roots
	envelope := new(bytes.Buffer)

	updatedIndex := make([]stripIndexEntry, 0, len(r.index))
	for _, ent := range r.index {
		sb := transBuf[ent.StripIndex]
		lv := leaves[ent.StripIndex]

		written, err := r.flushTransitions(ctx, ent, sb)
		if err != nil {
			return nil, err
		}
		envelope.Write(written)

		root := merkleRoot(lv)
		res.perStripRoot[ent.StripIndex] = root
		ent.TransitionsMerkleRoot = root

		avgResid := avg(res.residuals)
		meta := routingMeta{
			Version:         "filpf52-demo",
			CreatedUnix:     time.Now().Unix(),
			CycleIndex:      cycleIndex,
			NumHops:         r.numHops,
			CellBytes:       int(r.cellBytes),
			NumCells:        r.numCells,
			Mobius:          true,
			SeedTag:         seedTag,
			TransitionsRoot: hex.EncodeToString(root[:]),
			TransitionsBytes: len(written),
			AvgResidual:     avgResid,
			PackedVsRaw:     float64(res.packedBytes) / float64(max(1, res.rawBytes)),
		}
		rc, err := r.writeRoutingMeta(ctx, ent, meta)
		if err != nil {
			return nil, err
		}
		ent.RoutingCRC32 = rc

		hc, err := r.writeRecoveryHints(ctx, ent, hints[ent.StripIndex])
		if err != nil {
			return nil, err
		}
		ent.RecoveryCRC32 = hc

		updatedIndex = append(updatedIndex, ent)
	}

	// Update global strip index with roots + CRCs
	if err := writeStripIndex(ctx, r.tr, r.f, r.gh, updatedIndex); err != nil {
		return nil, err
	}

	res.envelopeB64 = fixedSizeB64(envelope.Bytes(), r.outB64Chars)
	return res, nil
}

func avg(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func main() {
	var (
		path         = flag.String("path", "fil.pagefile", "pagefile path to create/use")
		stripMB      = flag.Int("strip-mb", 256, "strip size in MiB (per strip)")
		strips       = flag.Int("strips", 6, "number of strips (pagefile bands)")
		cellBytes    = flag.Int("cell-bytes", 4096, "cell size in bytes (power of two)")
		headroomPct  = flag.Float64("headroom-pct", 1.5, "percent of each strip reserved for headroom")
		// headroom split (percent weights, normalized)
		transPct     = flag.Float64("headroom-transitions", 70, "headroom split weight: transitions")
		routingPct   = flag.Float64("headroom-routing", 20, "headroom split weight: routing metadata")
		recoverPct   = flag.Float64("headroom-recovery", 10, "headroom split weight: recovery hints")

		batches      = flag.Int("batches", 2, "number of batches")
		batchBytes   = flag.Int("batch-bytes", 65536, "batch size in bytes")
		outChars     = flag.Int("out-b64-chars", 8192, "fixed Base64 output envelope size (chars)")
		deflateLevel = flag.Int("deflate-level", flate.BestSpeed, "DEFLATE level (1..9)")
		zipkinURL    = flag.String("zipkin", "http://localhost:9411/api/v2/spans", "Zipkin endpoint (Jaeger can ingest). Empty disables network export.")
		service      = flag.String("service", "filv5.2-userland-driver", "service name for tracing")
	)
	flag.Parse()

	if *strips < 1 {
		log.Fatal("strips must be >= 1")
	}

	tr := newTracer(*service)
	ctx := context.Background()

	stripBytes := uint64(*stripMB) << 20
	lay, err := computeLayout(stripBytes, uint32(*cellBytes), *headroomPct, *transPct, *routingPct, *recoverPct)
	if err != nil {
		log.Fatalf("layout error: %v", err)
	}

	usablePerStrip := lay.cellRegionBytes
	cellsPerGiB := float64(lay.numCells) / (float64(lay.stripBytes) / float64(1<<30))
	log.Printf("layout: strips=%d strip=%d bytes (%.2f GiB) cell=%d headroom=%.2f%%", *strips, lay.stripBytes, float64(lay.stripBytes)/float64(1<<30), lay.cellBytes, lay.headroomPct)
	log.Printf("layout: stripHeader=%d headroom=%d cellRegion=%d numCells=%d usable=%d", lay.stripHeaderBytes, lay.headroomBytes, lay.cellRegionBytes, lay.numCells, usablePerStrip)
	log.Printf("layout: cellsPerGiB=%.2f bytesPerCell=%d headroomSplit=(T %.2f, R %.2f, H %.2f)",
		cellsPerGiB, lay.cellBytes, lay.transitionsPct, lay.routingPct, lay.recoveryPct)

	if err := initContainer(ctx, tr, *path, lay, uint32(*strips)); err != nil {
		log.Fatalf("initContainer error: %v", err)
	}

	r := &runner{
		tr:           tr,
		path:         *path,
		outB64Chars:  *outChars,
		deflateLevel: *deflateLevel,
		numHops:      36, // 3 nodes × 12 layers
	}
	if err := r.open(); err != nil {
		log.Fatalf("open error: %v", err)
	}
	defer r.close()

	ctx, sp := tr.Start(ctx, "run.all", map[string]string{
		"batches":    fmt.Sprint(*batches),
		"batchBytes": fmt.Sprint(*batchBytes),
		"go":         runtime.Version(),
	})
	defer sp.End()

	for i := 0; i < *batches; i++ {
		batch := make([]byte, *batchBytes)
		_, _ = rand.Read(batch)
		seedTag := fmt.Sprintf("b%d-%d", i, time.Now().UnixNano())

		res, err := r.runCycle(ctx, batch, i, seedTag)
		if err != nil {
			log.Fatalf("cycle %d error: %v", i, err)
		}
		avgResid := avg(res.residuals)
		okPacked := (res.packedBytes <= res.rawBytes)

		// show per-strip roots
		keys := make([]int, 0, len(res.perStripRoot))
		for k := range res.perStripRoot { keys = append(keys, int(k)) }
		sort.Ints(keys)
		var rootSummary string
		for _, k := range keys {
			root := res.perStripRoot[uint32(k)]
			rootSummary += fmt.Sprintf(" strip%d=%s", k, hex.EncodeToString(root[:8]))
		}

		log.Printf("cycle=%d raw=%d packed=%d ratio=%.3f avgResidual=%.6f packed<=raw=%v roots:%s",
			i, res.rawBytes, res.packedBytes, float64(res.packedBytes)/float64(max(1, res.rawBytes)), avgResid, okPacked, rootSummary)

		if i == *batches-1 {
			fmt.Printf("\n---- FIXED HITC ENVELOPE (Base64, %d chars) ----\n%s\n\n", len(res.envelopeB64), res.envelopeB64)
		}
	}

	_ = tr.Flush(context.Background(), *zipkinURL, "trace_spans.json")
}
