// Copyright (c) 2019 The BFE Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bfe_bufio implements buffered I/O.  It wraps an io.Reader or io.Writer
// object, creating another object (Reader or Writer) that also implements
// the interface but provides buffering and some help for textual I/O.
package bfe_bufio

import (
	"bytes"
	"errors"
	"io"
	"unicode/utf8"
)

import (
	"github.com/baidu/go-lib/log"
)

const (
	defaultBufSize = 4096 // 默认的缓冲区大小
)

var (
	ErrInvalidUnreadByte = errors.New("bfe_bufio: invalid use of UnreadByte")
	ErrInvalidUnreadRune = errors.New("bfe_bufio: invalid use of UnreadRune")
	ErrBufferFull        = errors.New("bfe_bufio: buffer full")
	ErrNegativeCount     = errors.New("bfe_bufio: negative count")
)

// Buffered input.

// Reader implements buffering for an io.Reader object.
// 实现io.Reader缓冲读。
type Reader struct {
	buf          []byte
	rd           io.Reader
	r, w         int   //buf read and write positions
	err          error // 读取中的err
	lastByte     int   // 记录最后一次ReadByte()的字符
	lastRuneSize int

	// 总读字节数
	TotalRead int // number of bytes total read
}

// 最小的读缓冲区的大小
const minReadBufferSize = 16

// NewReaderSize returns a new Reader whose buffer has at least the specified
// size. If the argument io.Reader is already a Reader with large enough
// size, it returns the underlying Reader.
// NewReaderSize返回一个新的Reader，它的缓冲区至少有指定的大小。如果参数io.Reader已经是一个足够大的Reader，它返回底层的Reader。
func NewReaderSize(rd io.Reader, size int) *Reader {
	// Is it already a Reader?
	// 已经是个缓冲读对象，并且buf大小满足size条件
	b, ok := rd.(*Reader)
	if ok && len(b.buf) >= size {
		return b
	}
	if size < minReadBufferSize {
		size = minReadBufferSize
	}
	// 创建并重置
	r := new(Reader)
	r.reset(make([]byte, size), rd)
	return r
}

// NewReader returns a new Reader whose buffer has the default size.
// 返回一个新的Reader，它的缓冲区具有默认大小。
func NewReader(rd io.Reader) *Reader {
	return NewReaderSize(rd, defaultBufSize)
}

// Reset discards any buffered data, resets all state, and switches
// the buffered reader to read from r.
// Reset丢弃任何缓存的数据，重置所有状态，并将缓存读取器切换到从r读取数据。
func (b *Reader) Reset(r io.Reader) {
	b.reset(b.buf, r)
}

// 重置缓冲
func (b *Reader) reset(buf []byte, r io.Reader) {
	*b = Reader{
		buf:          buf, // 没有清空
		rd:           r,
		lastByte:     -1,
		lastRuneSize: -1,
		TotalRead:    0,
	}
}

var errNegativeRead = errors.New("bfe_bufio: reader returned negative count from Read")

// fill reads a new chunk into the buffer.
// 将一个新数据块读入缓冲区。
func (b *Reader) fill() {
	// Slide existing data to beginning.
	// 将现有数据滑动到起始位置。
	if b.r > 0 {
		copy(b.buf, b.buf[b.r:b.w])
		b.w -= b.r
		b.r = 0
	}

	// Read new data.
	// 读取新的数据.最多[b.w:]长度
	n, err := b.rd.Read(b.buf[b.w:])
	if n < 0 {
		panic(errNegativeRead)
	}

	// read读取的长度正常不会超过buf长度
	if (b.w + n) > len(b.buf) {
		log.Logger.Warn("bfe_bufio:reader.fill(),len(buf)=%d,b.r=%d,b.w=%d,n=%d\n",
			len(b.buf), b.r, b.w, n)
	}

	b.w += n
	if err != nil {
		b.err = err
	}
}

func (b *Reader) readErr() error {
	err := b.err
	b.err = nil
	return err
}

// Peek returns the next n bytes without advancing the reader. The bytes stop
// being valid at the next read call. If Peek returns fewer than n bytes, it
// also returns an error explaining why the read is short. The error is
// ErrBufferFull if n is larger than b's buffer size.
// Peek返回下一个n字节，不前进读取器。字节在下一次读取调用时停止有效。
// 如果Peek返回小于n个字节，它还返回一个错误，解释为什么读取时间短。如果n大于b的缓冲区大小，则错误为ErrBufferFull。
func (b *Reader) Peek(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrNegativeCount
	}
	if n > len(b.buf) {
		return nil, ErrBufferFull
	}
	// 现有缓冲区数据不足n，进行填充，直到fill填入err
	for b.w-b.r < n && b.err == nil {
		b.fill()
	}
	// 可读取的长度
	m := b.w - b.r
	if m > n {
		m = n
	}
	// 不足n返回错误
	var err error
	if m < n {
		err = b.readErr()
		if err == nil {
			err = ErrBufferFull
		}
	}
	return b.buf[b.r : b.r+m], err
}

// Read reads data into p.
// It returns the number of bytes read into p.
// It calls Read at most once on the underlying Reader,
// hence n may be less than len(p).
// At EOF, the count will be zero and err will be io.EOF.
func (b *Reader) Read(p []byte) (n int, err error) {
	n = len(p)
	if n == 0 {
		return 0, b.readErr()
	}
	if b.w == b.r {
		if b.err != nil {
			return 0, b.readErr()
		}
		if len(p) >= len(b.buf) {
			// Large read, empty buffer.
			// Read directly into p to avoid copy.
			n, b.err = b.rd.Read(p)
			if n > 0 {
				b.lastByte = int(p[n-1])
				b.lastRuneSize = -1

				b.TotalRead += n
			}

			return n, b.readErr()
		}
		b.fill()
		if b.w == b.r {
			return 0, b.readErr()
		}
	}

	if n > b.w-b.r {
		n = b.w - b.r
	}

	if b.r > len(b.buf) || (b.r+n) > len(b.buf) {
		log.Logger.Warn("bfe_bufio:reader.Read(),len(buf)=%d,b.r=%d,b.w=%d,n=%d\n",
			len(b.buf), b.r, b.w, n)
	}

	copy(p[0:n], b.buf[b.r:])
	b.r += n
	b.lastByte = int(b.buf[b.r-1])
	b.lastRuneSize = -1

	b.TotalRead += n

	return n, nil
}

// ReadByte reads and returns a single byte.
// If no byte is available, returns an error.
// 读取并返回单个字节。如果没有可用的字节，则返回错误。
func (b *Reader) ReadByte() (c byte, err error) {
	b.lastRuneSize = -1
	// 缓冲区中没有数据，填写数据
	for b.w == b.r {
		if b.err != nil {
			return 0, b.readErr()
		}
		b.fill()
	}
	c = b.buf[b.r]
	b.r++
	b.lastByte = int(c)

	b.TotalRead += 1

	return c, nil
}

// UnreadByte unreads the last byte.  Only the most recently read byte can be unread.
// 取消读取最后一个字节。只有最近读的字节可以被取消读。
func (b *Reader) UnreadByte() error {
	b.lastRuneSize = -1
	// 缓冲区空了
	if b.r == b.w && b.lastByte >= 0 {
		b.w = 1
		b.r = 0
		// 写入最后的字符
		b.buf[0] = byte(b.lastByte)
		b.lastByte = -1

		// 减少计数
		if b.TotalRead > 0 {
			b.TotalRead -= 1
		}

		return nil
	}
	// 没法回退了
	if b.r <= 0 {
		return ErrInvalidUnreadByte
	}
	b.r--
	b.lastByte = -1

	if b.TotalRead > 0 {
		b.TotalRead -= 1
	}

	return nil
}

// ReadRune reads a single UTF-8 encoded Unicode character and returns the
// rune and its size in bytes. If the encoded rune is invalid, it consumes one byte
// and returns unicode.ReplacementChar (U+FFFD) with a size of 1.
func (b *Reader) ReadRune() (r rune, size int, err error) {
	for b.r+utf8.UTFMax > b.w && !utf8.FullRune(b.buf[b.r:b.w]) && b.err == nil {
		b.fill()
	}
	b.lastRuneSize = -1
	if b.r == b.w {
		return 0, 0, b.readErr()
	}
	r, size = rune(b.buf[b.r]), 1
	if r >= 0x80 {
		r, size = utf8.DecodeRune(b.buf[b.r:b.w])
	}
	b.r += size
	b.lastByte = int(b.buf[b.r-1])
	b.lastRuneSize = size

	b.TotalRead += size

	return r, size, nil
}

// UnreadRune unreads the last rune.  If the most recent read operation on
// the buffer was not a ReadRune, UnreadRune returns an error.  (In this
// regard it is stricter than UnreadByte, which will unread the last byte
// from any read operation.)
func (b *Reader) UnreadRune() error {
	if b.lastRuneSize < 0 || b.r == 0 {
		return ErrInvalidUnreadRune
	}
	b.r -= b.lastRuneSize

	if b.TotalRead >= b.lastRuneSize {
		b.TotalRead -= b.lastRuneSize
	}

	b.lastByte = -1
	b.lastRuneSize = -1

	return nil
}

// Buffered returns the number of bytes that can be read from the current buffer.
// 返回可从当前缓冲区读取的字节数。
func (b *Reader) Buffered() int { return b.w - b.r }

// ReadSlice reads until the first occurrence of delim in the input,
// returning a slice pointing at the bytes in the buffer.
// The bytes stop being valid at the next read.
// If ReadSlice encounters an error before finding a delimiter,
// it returns all the data in the buffer and the error itself (often io.EOF).
// ReadSlice fails with error ErrBufferFull if the buffer fills without a delim.
// Because the data returned from ReadSlice will be overwritten
// by the next I/O operation, most clients should use
// ReadBytes or ReadString instead.
// ReadSlice returns err != nil if and only if line does not end in delim.
// 多次调用不会重复返回
func (b *Reader) ReadSlice(delim byte) (line []byte, err error) {
	// Look in buffer.
	// 现有的buf中已经有delim字符，直接返回
	if i := bytes.IndexByte(b.buf[b.r:b.w], delim); i >= 0 {
		line1 := b.buf[b.r : b.r+i+1] // 返回的数据
		b.r += i + 1                  // 重置已读取的位置

		b.TotalRead += i + 1 // 记录已被读取的长度

		return line1, nil
	}

	// Read more into buffer, until buffer fills or we find delim.
	// 向缓冲区中读入更多的内容，直到缓冲区填满或找到delim。
	for {
		// 有异常，返回所有数据
		if b.err != nil {
			line := b.buf[b.r:b.w]

			b.TotalRead += b.w - b.r

			b.r = b.w
			return line, b.readErr()
		}

		// 当前缓冲里没有delim字符,接着填充数据
		n := b.Buffered()
		b.fill()

		// Search new part of buffer
		// 填充之后检查有没有delim字符
		if i := bytes.IndexByte(b.buf[n:b.w], delim); i >= 0 {
			line := b.buf[0 : n+i+1]
			b.r = n + i + 1

			b.TotalRead += i + 1

			return line, nil
		}

		// Buffer is full?
		// buff已经满了还没有delim字符，就直接返回所有数据
		if b.Buffered() >= len(b.buf) {
			b.TotalRead += len(b.buf)

			b.r = b.w
			return b.buf, ErrBufferFull
		}
	}
}

// ReadLine is a low-level line-reading primitive. Most callers should use
// ReadBytes('\n') or ReadString('\n') instead or use a Scanner.
//
// ReadLine tries to return a single line, not including the end-of-line bytes.
// If the line was too long for the buffer then isPrefix is set and the
// beginning of the line is returned. The rest of the line will be returned
// from future calls. isPrefix will be false when returning the last fragment
// of the line. The returned buffer is only valid until the next call to
// ReadLine. ReadLine either returns a non-nil line or it returns an error,
// never both.
//
// The text returned from ReadLine does not include the line end ("\r\n" or "\n").
// No indication or error is given if the input ends without a final line end.
// ReadLine要么返回非空行，要么返回错误，从不同时返回。
// 从ReadLine返回的文本不包括行尾("\r\n"或"\n")。
// 如果输入没有最后一行结束，则不会给出任何指示或错误。
func (b *Reader) ReadLine() (line []byte, isPrefix bool, err error) {
	line, err = b.ReadSlice('\n')
	if err == ErrBufferFull {
		// Handle the case where "\r\n" straddles the buffer.
		// 处理"\r\n"跨跨缓冲区的情况。
		if len(line) > 0 && line[len(line)-1] == '\r' {
			// Put the '\r' back on buf and drop it from line.
			// Let the next call to ReadLine check for "\r\n".
			// 将'\r'放回buf，并将其从行中删除。
			// 让下一次调用ReadLine检查“\r\n”。
			if b.r == 0 {
				// should be unreachable
				panic("bfe_bufio: tried to rewind past start of buffer")
			}
			b.r--
			line = line[:len(line)-1]
		}
		return line, true, nil
	}

	if len(line) == 0 {
		if err != nil {
			line = nil
		}
		return
	}
	err = nil

	// 去掉最后的\r\n
	if line[len(line)-1] == '\n' {
		drop := 1
		if len(line) > 1 && line[len(line)-2] == '\r' {
			drop = 2
		}
		line = line[:len(line)-drop]
	}
	return
}

// ReadBytes reads until the first occurrence of delim in the input,
// returning a slice containing the data up to and including the delimiter.
// If ReadBytes encounters an error before finding a delimiter,
// it returns the data read before the error and the error itself (often io.EOF).
// ReadBytes returns err != nil if and only if the returned data does not end in
// delim.
// For simple uses, a Scanner may be more convenient.
func (b *Reader) ReadBytes(delim byte) (line []byte, err error) {
	// Use ReadSlice to look for array,
	// accumulating full buffers.
	var frag []byte
	var full [][]byte
	err = nil

	for {
		var e error
		frag, e = b.ReadSlice(delim)
		if e == nil { // got final fragment
			break
		}
		if e != ErrBufferFull { // unexpected error
			err = e
			break
		}

		// Make a copy of the buffer.
		buf := make([]byte, len(frag))
		copy(buf, frag)
		full = append(full, buf)
	}

	// Allocate new buffer to hold the full pieces and the fragment.
	n := 0
	for i := range full {
		n += len(full[i])
	}
	n += len(frag)

	// Copy full pieces and fragment in.
	buf := make([]byte, n)
	n = 0
	for i := range full {
		n += copy(buf[n:], full[i])
	}
	copy(buf[n:], frag)
	return buf, err
}

// ReadString reads until the first occurrence of delim in the input,
// returning a string containing the data up to and including the delimiter.
// If ReadString encounters an error before finding a delimiter,
// it returns the data read before the error and the error itself (often io.EOF).
// ReadString returns err != nil if and only if the returned data does not end in
// delim.
// For simple uses, a Scanner may be more convenient.
func (b *Reader) ReadString(delim byte) (line string, err error) {
	bytes, err := b.ReadBytes(delim)
	line = string(bytes)
	return line, err
}

// WriteTo implements io.WriterTo.
func (b *Reader) WriteTo(w io.Writer) (n int64, err error) {
	n, err = b.writeBuf(w)
	if err != nil {
		return
	}

	if r, ok := b.rd.(io.WriterTo); ok {
		m, err := r.WriteTo(w)

		if m > 0 {
			b.TotalRead += int(m)
		}

		n += m
		return n, err
	}

	for b.fill(); b.r < b.w; b.fill() {
		m, err := b.writeBuf(w)
		n += m
		if err != nil {
			return n, err
		}
	}

	if b.err == io.EOF {
		b.err = nil
	}

	return n, b.readErr()
}

// writeBuf writes the Reader's buffer to the writer.
func (b *Reader) writeBuf(w io.Writer) (int64, error) {
	n, err := w.Write(b.buf[b.r:b.w])
	b.r += n

	if n > 0 {
		b.TotalRead += n
	}

	return int64(n), err
}

// buffered output

// Writer implements buffering for an io.Writer object.
// If an error occurs writing to a Writer, no more data will be
// accepted and all subsequent writes will return the error.
// After all data has been written, the client should call the
// Flush method to guarantee all data has been forwarded to
// the underlying io.Writer.
type Writer struct {
	err error
	buf []byte
	n   int
	wr  io.Writer

	// 总写入字节数
	TotalWrite int // number of bytes total write
}

// NewWriterSize returns a new Writer whose buffer has at least the specified
// size. If the argument io.Writer is already a Writer with large enough
// size, it returns the underlying Writer.
// NewWriterSize返回一个新的Writer，它的缓冲区至少有指定的大小。如果参数io.Writer已经是一个足够大的Writer，它返回底层的Writer。
func NewWriterSize(w io.Writer, size int) *Writer {
	// Is it already a Writer?
	b, ok := w.(*Writer)
	if ok && len(b.buf) >= size {
		return b
	}
	if size <= 0 {
		size = defaultBufSize
	}
	return &Writer{
		buf:        make([]byte, size),
		wr:         w,
		TotalWrite: 0,
	}
}

// NewWriter returns a new Writer whose buffer has the default size.
func NewWriter(w io.Writer) *Writer {
	return NewWriterSize(w, defaultBufSize)
}

// Reset discards any unflushed buffered data, clears any error, and
// resets b to write its output to w.
func (b *Writer) Reset(w io.Writer) {
	b.err = nil
	b.n = 0
	b.wr = w
	b.TotalWrite = 0
}

// Flush writes any buffered data to the underlying io.Writer.
// 将任何缓冲数据写入底层io.Writer。
func (b *Writer) Flush() error {
	err := b.flush()
	return err
}

func (b *Writer) flush() error {
	if b.err != nil {
		return b.err
	}
	if b.n == 0 {
		return nil
	}
	n, err := b.wr.Write(b.buf[0:b.n])
	if n < b.n && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		if n > 0 && n < b.n {
			copy(b.buf[0:b.n-n], b.buf[n:b.n])
		}
		b.n -= n
		b.err = err
		return err
	}
	b.n = 0
	return nil
}

// Available returns how many bytes are unused in the buffer.
// 返回缓冲区中未使用的字节数。
func (b *Writer) Available() int { return len(b.buf) - b.n }

// Buffered returns the number of bytes that have been written into the current buffer.
func (b *Writer) Buffered() int { return b.n }

// Write writes the contents of p into the buffer.
// It returns the number of bytes written.
// If nn < len(p), it also returns an error explaining
// why the write is short.
func (b *Writer) Write(p []byte) (nn int, err error) {
	for len(p) > b.Available() && b.err == nil {
		var n int
		if b.Buffered() == 0 {
			// Large write, empty buffer.
			// Write directly from p to avoid copy.
			n, b.err = b.wr.Write(p)
		} else {
			n = copy(b.buf[b.n:], p)
			b.n += n
			b.flush()
		}
		nn += n
		p = p[n:]
	}
	if b.err != nil {
		b.TotalWrite += nn
		return nn, b.err
	}
	n := copy(b.buf[b.n:], p)
	b.n += n
	nn += n

	b.TotalWrite += nn

	return nn, nil
}

// WriteByte writes a single byte.
func (b *Writer) WriteByte(c byte) error {
	if b.err != nil {
		return b.err
	}
	if b.Available() <= 0 && b.flush() != nil {
		return b.err
	}
	b.buf[b.n] = c
	b.n++
	b.TotalWrite++
	return nil
}

// WriteRune writes a single Unicode code point, returning
// the number of bytes written and any error.
func (b *Writer) WriteRune(r rune) (size int, err error) {
	if r < utf8.RuneSelf {
		err = b.WriteByte(byte(r))
		if err != nil {
			return 0, err
		}
		return 1, nil
	}
	if b.err != nil {
		return 0, b.err
	}
	n := b.Available()
	if n < utf8.UTFMax {
		if b.flush(); b.err != nil {
			return 0, b.err
		}
		n = b.Available()
		if n < utf8.UTFMax {
			// Can only happen if buffer is silly small.
			return b.WriteString(string(r))
		}
	}
	size = utf8.EncodeRune(b.buf[b.n:], r)

	b.TotalWrite += size

	b.n += size
	return size, nil
}

// WriteString writes a string.
// It returns the number of bytes written.
// If the count is less than len(s), it also returns an error explaining
// why the write is short.
func (b *Writer) WriteString(s string) (int, error) {
	nn := 0
	for len(s) > b.Available() && b.err == nil {
		n := copy(b.buf[b.n:], s)
		b.n += n
		nn += n
		s = s[n:]
		b.flush()
	}
	if b.err != nil {
		b.TotalWrite += nn
		return nn, b.err
	}
	n := copy(b.buf[b.n:], s)
	b.n += n
	nn += n
	b.TotalWrite += nn
	return nn, nil
}

// ReadFrom implements io.ReaderFrom.
func (b *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	if b.Buffered() == 0 {
		if w, ok := b.wr.(io.ReaderFrom); ok {
			n, err = w.ReadFrom(r)
			b.TotalWrite += int(n)
			return n, err
		}
	}
	var m int
	for {
		if b.Available() == 0 {
			if err1 := b.flush(); err1 != nil {
				return n, err1
			}
		}
		m, err = r.Read(b.buf[b.n:])
		if m == 0 {
			break
		}

		b.n += m

		if b.n > len(b.buf) {
			log.Logger.Warn("bfe_bufio:Writer.ReadFrom(),len(buf)=%d,b.n=%d,m=%d\n",
				len(b.buf), b.n, m)
		}

		n += int64(m)
		if err != nil {
			break
		}
	}
	if err == io.EOF {
		// If we filled the buffer exactly, flush pre-emptively.
		if b.Available() == 0 {
			err = b.flush()
		} else {
			err = nil
		}
	}
	b.TotalWrite += int(n)
	return n, err
}

// buffered input and output

// ReadWriter stores pointers to a Reader and a Writer.
// It implements io.ReadWriter.
// ReadWriter存储指向Reader和Writer的指针。
// 实现io.ReadWriter。
type ReadWriter struct {
	*Reader
	*Writer
}

// NewReadWriter allocates a new ReadWriter that dispatches to r and w.
// 分配一个新的读写器分派给r和w。
func NewReadWriter(r *Reader, w *Writer) *ReadWriter {
	return &ReadWriter{r, w}
}
