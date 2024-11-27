/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 Damian Peckett <damian@peckett>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package qcow2

import (
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
	"unsafe"

	"github.com/goburrow/cache"
)

const (
	// Each table is going to be around a single cluster in size.
	// So this will store up to 64MB of tables in memory.
	maxCachedTables = 1000
)

type Image struct {
	mu          sync.RWMutex
	f           io.ReaderAt
	hdr         *HeaderAndAdditionalFields
	tableCache  cache.LoadingCache
	clusterSize int64
	cursorMu    sync.Mutex
	cursor      int64
}

func Open(f io.ReaderAt) (*Image, error) {
	hdr, err := readHeader(f)
	if err != nil {
		return nil, err
	}

	i := &Image{
		f:           f,
		hdr:         hdr,
		clusterSize: int64(1 << hdr.ClusterBits),
	}

	i.tableCache = cache.NewLoadingCache(i.tableLoader,
		cache.WithMaximumSize(maxCachedTables),
	)

	return i, nil
}

func readHeader(r io.ReaderAt) (*HeaderAndAdditionalFields, error) {
	var hdr Header
	f := io.NewSectionReader(r, 0, math.MaxInt64)
	if err := binary.Read(f, binary.BigEndian, &hdr); err != nil {
		return nil, fmt.Errorf("failed to read image header: %w", err)
	}

	if hdr.Magic != Magic {
		return nil, fmt.Errorf("invalid magic bytes")
	}

	if hdr.Version != Version3 {
		return nil, fmt.Errorf("only version 3 is supported")
	}

	if hdr.BackingFileOffset != 0 {
		return nil, fmt.Errorf("backing files are not supported")
	}

	if hdr.CryptMethod != NoEncryption {
		return nil, fmt.Errorf("encryption is not supported")
	}

	if hdr.IncompatibleFeatures != 0 {
		return nil, fmt.Errorf("incompatible features are not supported")
	}

	var additionalFields *HeaderAdditionalFields
	if hdr.HeaderLength > uint32(unsafe.Sizeof(hdr)) {
		additionalFields = &HeaderAdditionalFields{}
		if err := binary.Read(f, binary.BigEndian, additionalFields); err != nil {
			return nil, fmt.Errorf("failed to read additional header fields: %w", err)
		}
	}

	if additionalFields != nil && additionalFields.CompressionType != CompressionTypeDeflate {
		return nil, fmt.Errorf("unsupported compression type")
	}

	var extensions []HeaderExtension
	for {
		var headerExtension HeaderExtension
		if err := binary.Read(f, binary.BigEndian, &headerExtension.HeaderExtensionMetadata); err != nil {
			return nil, fmt.Errorf("failed to read header extension type and length: %w", err)
		}

		if headerExtension.Type == EndOfHeaderExtensionArea {
			break
		}

		if headerExtension.Type == BackingFileFormatName ||
			headerExtension.Type == ExternalDataFileName ||
			headerExtension.Type == FullDiskEncryptionHeader {
			return nil, fmt.Errorf("unsupported header extension")
		}

		headerExtension.Data = make([]byte, headerExtension.Length)
		if _, err := io.ReadFull(f, headerExtension.Data); err != nil {
			return nil, fmt.Errorf("failed to read header extension data: %w", err)
		}

		extensions = append(extensions, headerExtension)
	}

	return &HeaderAndAdditionalFields{
		Header:           hdr,
		AdditionalFields: additionalFields,
		Extensions:       extensions,
	}, nil
}

func (i *Image) Size() (int64, error) {
	return int64(i.hdr.Size), nil
}

func (i *Image) Read(p []byte) (n int, err error) {
	i.cursorMu.Lock()
	defer i.cursorMu.Unlock()

	n, err = i.ReadAt(p, i.cursor)
	i.cursor += int64(n)
	return
}

func (i *Image) ReadAt(p []byte, diskOffset int64) (n int, err error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	n = len(p)
	if n == 0 {
		return
	}

	if diskOffset+int64(n) > int64(i.hdr.Size) {
		n = int(int64(i.hdr.Size) - diskOffset)
		p = p[:n]
		err = io.EOF
	}

	remaining := n
	for remaining > 0 {
		r, err := i.clusterReader(diskOffset)
		if err != nil {
			return n - remaining, err
		}

		bytesInCluster, err := r.Read(p[:min(int64(i.clusterSize), int64(remaining))])
		if err != nil && err != io.EOF {
			return n - remaining, err
		}

		// advance to the next cluster.
		diskOffset += int64(bytesInCluster)
		p = p[bytesInCluster:]
		remaining -= bytesInCluster
	}

	return
}

type tableKey struct {
	imageOffset int64
	n           int
}

func (i *Image) tableLoader(key cache.Key) (cache.Value, error) {
	imageOffset := key.(tableKey).imageOffset
	n := key.(tableKey).n

	buf := make([]byte, 8*n)
	if _, err := i.f.ReadAt(buf, imageOffset); err != nil {
		return nil, fmt.Errorf("failed to read table: %w", err)
	}

	t := make([]uint64, n)
	for i := range t {
		t[i] = binary.BigEndian.Uint64(buf[i*8 : (i+1)*8])
	}

	return t, nil
}

func (i *Image) readTable(imageOffset int64, n int) ([]uint64, error) {
	t, err := i.tableCache.Get(tableKey{imageOffset: imageOffset, n: n})
	if err != nil {
		return nil, fmt.Errorf("failed to read table: %w", err)
	}

	return t.([]uint64), nil
}

func (i *Image) getRefcount(diskOffset int64) (uint64, error) {
	refcountOffset, err := i.diskToRefcountOffset(diskOffset)
	if err != nil {
		return 0, err
	}

	refcountBits := int64(1 << i.hdr.RefcountOrder)
	return readBits(i.f, refcountOffset, refcountBits)
}

func (i *Image) diskToRefcountOffset(diskOffset int64) (int64, error) {
	refcountBits := int64(1 << i.hdr.RefcountOrder)

	refcountBlockEntries := i.clusterSize * 8 / refcountBits

	refcountBlockIndex := (diskOffset / i.clusterSize) % refcountBlockEntries
	refcountTableIndex := (diskOffset / i.clusterSize) / refcountBlockEntries

	refCountTableEntries := (int64(i.hdr.RefcountTableClusters) * i.clusterSize) / 8
	refCountTable, err := i.readTable(int64(i.hdr.RefcountTableOffset), int(refCountTableEntries))
	if err != nil {
		return 0, err
	}

	refcountBlockOffset := int64(refCountTable[refcountTableIndex] &^ ((1 << 9) - 1))

	return refcountBlockOffset + refcountBlockIndex*refcountBits, nil
}

func readBits(f io.ReaderAt, imageOffset int64, nBits int64) (uint64, error) {
	nBytes := (nBits + 7) / 8
	buf := make([]byte, nBytes)

	if _, err := f.ReadAt(buf, imageOffset); err != nil {
		return 0, fmt.Errorf("failed to read bits: %w", err)
	}

	var bits uint64
	for bitIdx := 0; bitIdx < int(nBits); bitIdx++ {
		bits <<= 1
		byteIdx := bitIdx / 8
		bitPosition := 7 - (bitIdx % 8)
		if buf[byteIdx]&(1<<bitPosition) != 0 {
			bits |= 1
		}
	}

	return bits, nil
}

func (i *Image) clusterReader(diskOffset int64) (io.Reader, error) {
	bytesRemainingInCluster := i.clusterSize - (diskOffset % i.clusterSize)

	l2Entries := i.clusterSize / 8
	l2Index := (diskOffset / i.clusterSize) % l2Entries
	l1Index := (diskOffset / i.clusterSize) / l2Entries

	l1Table, err := i.readTable(int64(i.hdr.L1TableOffset), int(i.hdr.L1Size))
	if err != nil {
		return nil, err
	}

	l1Entry := L1TableEntry(l1Table[l1Index])

	l2TableOffset := l1Entry.Offset()

	l2Table, err := i.readTable(l2TableOffset, int(l2Entries))
	if err != nil {
		return nil, err
	}

	l2Entry := L2TableEntry(l2Table[l2Index])

	// Is it a hole?
	if l2Entry.Unallocated() {
		return io.LimitReader(zeroReader{}, int64(bytesRemainingInCluster)), nil
	}

	// Is it a compressed cluster?
	if l2Entry.Compressed() {
		imageOffset := l2Entry.Offset(i.hdr)

		fr := flate.NewReader(io.NewSectionReader(i.f, imageOffset, l2Entry.CompressedSize(i.hdr)))

		if _, err := io.CopyN(io.Discard, fr, diskOffset%i.clusterSize); err != nil {
			return nil, err
		}

		return io.LimitReader(fr, int64(bytesRemainingInCluster)), nil
	}

	imageOffset := l2Entry.Offset(i.hdr) + (diskOffset % i.clusterSize)

	return io.NewSectionReader(i.f, imageOffset, int64(bytesRemainingInCluster)), nil
}

func (i *Image) diskToImageOffset(diskOffset int64) (int64, L2TableEntry, error) {
	clusterSize := int64(1 << i.hdr.ClusterBits)

	l2Entries := clusterSize / 8
	l2Index := (diskOffset / clusterSize) % l2Entries
	l1Index := (diskOffset / clusterSize) / l2Entries

	l1Table, err := i.readTable(int64(i.hdr.L1TableOffset), int(i.hdr.L1Size))
	if err != nil {
		return 0, 0, err
	}

	l1Entry := L1TableEntry(l1Table[l1Index])

	l2Table, err := i.readTable(l1Entry.Offset(), int(l2Entries))
	if err != nil {
		return 0, 0, err
	}

	l2Entry := L2TableEntry(l2Table[l2Index])

	return l2Entry.Offset(i.hdr) + (diskOffset % clusterSize), l2Entry, nil
}

func (i *Image) alignToClusterBoundary(offset int64) int64 {
	return i.clusterSize * (offset / i.clusterSize)
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// zeroReader is a reader that reads zeros.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
