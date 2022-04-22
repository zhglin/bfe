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

package bfe_http

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
)

import (
	"github.com/bfenetworks/bfe/bfe_bufio"
	"github.com/bfenetworks/bfe/bfe_net/textproto"
)

// transferWriter inspects the fields of a user-supplied Request or Response,
// sanitizes them without changing the user object and provides methods for
// writing the respective header, body and trailer in wire format.
type transferWriter struct {
	Method           string
	Body             io.Reader
	BodyCloser       io.Closer
	ResponseToHEAD   bool
	Close            bool
	ContentLength    int64 // -1 means unknown, 0 means exactly none
	TransferEncoding []string
	Header           Header
	Trailer          Header
}

func newTransferWriter(r interface{}) (t *transferWriter, err error) {
	t = &transferWriter{}

	// Extract relevant fields
	atLeastHTTP11 := false
	switch rr := r.(type) {
	case *Request:
		if rr.ContentLength != 0 && rr.Body == nil {
			return nil, fmt.Errorf("http: Request.ContentLength=%d with nil Body", rr.ContentLength)
		}
		t.Method = rr.Method
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = rr.ContentLength
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Header = rr.Header
		t.Trailer = rr.Trailer
		atLeastHTTP11 = rr.ProtoAtLeast(1, 1)
		if t.Body != nil && len(t.TransferEncoding) == 0 && atLeastHTTP11 {
			if t.ContentLength == 0 {
				// Test to see if it's actually zero or just unset.
				var buf [1]byte
				n, _ := io.ReadFull(t.Body, buf[:])
				if n == 1 {
					// Oh, guess there is data in this Body Reader after all.
					// The ContentLength field just wasn't set.
					// Stich the Body back together again, re-attaching our
					// consumed byte.
					t.ContentLength = -1
					t.Body = io.MultiReader(bytes.NewBuffer(buf[:]), t.Body)
				} else {
					// Body is actually empty.
					t.Body = nil
					t.BodyCloser = nil
				}
			}
			if t.ContentLength < 0 {
				t.TransferEncoding = []string{"chunked"}
			}
		}
	case *Response:
		if rr.Request != nil {
			t.Method = rr.Request.Method
		}
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = rr.ContentLength
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Header = rr.Header
		t.Trailer = rr.Trailer
		atLeastHTTP11 = rr.ProtoAtLeast(1, 1)
		t.ResponseToHEAD = noBodyExpected(t.Method)
	}

	// Sanitize Body,ContentLength,TransferEncoding
	if t.ResponseToHEAD {
		t.Body = nil
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		}
	} else {
		if !atLeastHTTP11 || t.Body == nil {
			t.TransferEncoding = nil
		}
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		} else if t.Body == nil { // no chunking, no body
			t.ContentLength = 0
		}
	}

	// Sanitize Trailer
	if !chunked(t.TransferEncoding) {
		t.Trailer = nil
	}

	return t, nil
}

// 没有body的method
func noBodyExpected(requestMethod string) bool {
	return requestMethod == MethodHead
}

func (t *transferWriter) shouldSendContentLength() bool {
	if chunked(t.TransferEncoding) {
		return false
	}
	if t.ContentLength > 0 {
		return true
	}

	// contentLength is 0, but have Content-Length in origin header
	// Some backends expect a Content-Length header
	if t.ContentLength == 0 && t.Header.Get("Content-Length") != "" {
		if t.Method == "GET" || t.Method == "HEAD" {
			return false
		}
		return true
	}

	return false
}

func (t *transferWriter) WriteHeader(w io.Writer) (err error) {
	if t.Close {
		_, err = io.WriteString(w, "Connection: close\r\n")
		if err != nil {
			return
		}
	}

	// Write Content-Length and/or Transfer-Encoding whose values are a
	// function of the sanitized field triple (Body, ContentLength,
	// TransferEncoding)
	if t.shouldSendContentLength() {
		io.WriteString(w, "Content-Length: ")
		_, err = io.WriteString(w, strconv.FormatInt(t.ContentLength, 10)+"\r\n")
		if err != nil {
			return
		}
	} else if chunked(t.TransferEncoding) {
		_, err = io.WriteString(w, "Transfer-Encoding: chunked\r\n")
		if err != nil {
			return
		}
	}

	// Write Trailer header
	if t.Trailer != nil {
		// TODO: At some point, there should be a generic mechanism for
		// writing long headers, using HTTP line splitting
		io.WriteString(w, "Trailer: ")
		needComma := false
		for k := range t.Trailer {
			k = CanonicalHeaderKey(k)
			switch k {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				return &badStringError{"invalid Trailer key", k}
			}
			if needComma {
				io.WriteString(w, ",")
			}
			io.WriteString(w, k)
			needComma = true
		}
		_, err = io.WriteString(w, "\r\n")
	}

	return
}

func (t *transferWriter) WriteBody(w io.Writer) (ncopy int64, err error) {
	// Write body
	if t.Body != nil {

		if chunked(t.TransferEncoding) {
			cw := newChunkedWriter(w)
			_, err = io.Copy(cw, t.Body)
			if err == nil {
				err = cw.Close()
			}
		} else if t.ContentLength == -1 {
			ncopy, err = io.Copy(w, t.Body)
		} else {
			ncopy, err = io.Copy(w, io.LimitReader(t.Body, t.ContentLength))
			if err != nil {
				return
			}
			var nextra int64
			nextra, err = io.Copy(ioutil.Discard, t.Body)
			ncopy += nextra
		}
		if err != nil {
			return
		}
		if err = t.BodyCloser.Close(); err != nil {
			return
		}
	}

	if !t.ResponseToHEAD && t.ContentLength != -1 && t.ContentLength != ncopy {
		err = fmt.Errorf("http: Request.ContentLength=%d with Body length %d",
			t.ContentLength, ncopy)
		return
	}

	// TODO(petar): Place trailer writer code here.
	if chunked(t.TransferEncoding) {
		// Last chunk, empty trailer
		_, err = io.WriteString(w, "\r\n")
	}

	return
}

// 可以把它理解为http的内部处理或者转换操作
type transferReader struct {
	// Input
	Header        Header // header头
	StatusCode    int    // 状态码
	RequestMethod string // http method
	ProtoMajor    int    // 大版本号
	ProtoMinor    int    // 小版本号
	// Output
	Body             io.ReadCloser
	ContentLength    int64    // body长度
	TransferEncoding []string // 传输编码 chunked
	Close            bool
	Trailer          Header //会实现说明在报文主体后记录哪些首部字段,该首部字段可以使用在 HTTP/1.1 版本分块传输编码时
}

// bodyAllowedForStatus reports whether a given response status code
// permits a body.  See RFC2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= StatusContinue && status <= 199:
		return false
	case status == StatusNoContent:
		return false
	case status == StatusNotModified:
		return false
	}
	return true
}

// msg is *Request or *Response.
func readTransfer(msg interface{}, r *bfe_bufio.Reader) (err error) {
	t := &transferReader{RequestMethod: MethodGet}

	// Unify input
	isResponse := false
	switch rr := msg.(type) {
	case *Response:
		t.Header = rr.Header
		t.StatusCode = rr.StatusCode
		t.ProtoMajor = rr.ProtoMajor
		t.ProtoMinor = rr.ProtoMinor
		t.Close = shouldClose(t.ProtoMajor, t.ProtoMinor, t.Header)
		isResponse = true
		if rr.Request != nil {
			t.RequestMethod = rr.Request.Method
		}
	case *Request:
		t.Header = rr.Header
		t.RequestMethod = rr.Method
		t.ProtoMajor = rr.ProtoMajor
		t.ProtoMinor = rr.ProtoMinor
		// Transfer semantics for Requests are exactly like those for
		// Responses with status code 200, responding to a GET method
		// 请求的传输语义与状态码为200的响应完全相同，响应一个GET方法
		t.StatusCode = StatusOK
	default:
		panic("unexpected type")
	}

	// Default to HTTP/1.1
	if t.ProtoMajor == 0 && t.ProtoMinor == 0 {
		t.ProtoMajor, t.ProtoMinor = 1, 1
	}

	// Transfer encoding, content length
	// 传输编码chunked，内容长度
	t.TransferEncoding, err = fixTransferEncoding(isResponse, t.RequestMethod, t.Header)
	if err != nil {
		return err
	}

	// context-length头
	realLength, err := fixLength(isResponse, t.StatusCode, t.RequestMethod, t.Header, t.TransferEncoding)
	if err != nil {
		return err
	}

	// 如果是repose && method == head
	if isResponse && t.RequestMethod == MethodHead {
		// HEAD方法与GET方法相同，只是服务器不能在响应中返回消息体。
		if n, err := parseContentLength(t.Header.GetDirect("Content-Length")); err != nil {
			return err
		} else {
			t.ContentLength = n
		}
	} else {
		t.ContentLength = realLength
	}

	// Trailer
	t.Trailer, err = fixTrailer(t.Header, t.TransferEncoding)
	if err != nil {
		return err
	}

	// If there is no Content-Length or chunked Transfer-Encoding on a *Response
	// and the status is not 1xx, 204 or 304, then the body is unbounded.
	// See RFC2616, section 4.4.
	//如果在*Response上没有Content-Length或chunked Transfer-Encoding
	//如果状态不是1xx, 204或304，那么body就是未绑定的。
	//参见RFC2616，章节4.4。
	switch msg.(type) {
	case *Response:
		if realLength == -1 &&
			!chunked(t.TransferEncoding) &&
			bodyAllowedForStatus(t.StatusCode) {
			// Unbounded body.
			t.Close = true
		}
	}

	// Prepare body reader.  ContentLength < 0 means chunked encoding
	// or close connection when finished, since multipart is not supported yet
	// 注意这里ContentLength < 0 表示 chunked encoding 或者已经接受完数据，关闭连接
	switch {
	case chunked(t.TransferEncoding): // chunked读取
		if noBodyExpected(t.RequestMethod) { // 没有body的method
			t.Body = EofReader
		} else {
			t.Body = &body{src: newChunkedReader(r), hdr: msg, r: r, closing: t.Close}
		}
	case realLength == 0: // 没有长度需要读取
		t.Body = EofReader
	case realLength > 0:
		// weiwei02: set r for peek data from body
		t.Body = &body{src: io.LimitReader(r, realLength), r: r, closing: t.Close}
	default:
		// realLength < 0, i.e. "Content-Length" not mentioned in header
		if t.Close {
			// Close semantics (i.e. HTTP/1.0)
			t.Body = &body{src: r, closing: t.Close}
		} else {
			// Persistent connection (i.e. HTTP/1.1) 持久连接
			t.Body = EofReader
		}
	}

	// Unify output 统一的输出
	switch rr := msg.(type) {
	case *Request:
		rr.Body = t.Body
		rr.ContentLength = t.ContentLength
		rr.TransferEncoding = t.TransferEncoding
		rr.Close = t.Close
		rr.Trailer = t.Trailer
	case *Response:
		rr.Body = t.Body
		rr.ContentLength = t.ContentLength
		rr.TransferEncoding = t.TransferEncoding
		rr.Close = t.Close
		rr.Trailer = t.Trailer
	}

	return nil
}

// Checks whether chunked is part of the encodings stack
// 检查chunked是否属于编码堆栈的一部分
func chunked(te []string) bool { return len(te) > 0 && te[0] == "chunked" }

// Checks whether the encoding is explicitly "identity".
func isIdentity(te []string) bool { return len(te) == 1 && te[0] == "identity" }

// Sanitize transfer encoding
// https://cloud.tencent.com/developer/article/1906632
// 返回传输编码 只支持chunked
func fixTransferEncoding(isResponse bool, requestMethod string, header Header) ([]string, error) {
	// 没设置传输编码就直接退出
	raw, present := header["Transfer-Encoding"]
	if !present {
		return nil, nil
	}

	delete(header, "Transfer-Encoding")

	encodings := strings.Split(raw[0], ",")
	te := make([]string, 0, len(encodings))
	// TODO: Even though we only support "identity" and "chunked"
	// encodings, the loop below is designed with foresight. One
	// invariant that must be maintained is that, if present,
	// chunked encoding must always come first.
	// TODO:尽管我们只支持“identity”和“chunked”编码，但下面的循环设计是有远见的。必须维护的一个不变量是，如果存在，分块编码必须总是先出现。
	for _, encoding := range encodings {
		encoding = strings.ToLower(strings.TrimSpace(encoding))
		// "identity" encoding is not recorded
		// "identity"的不记录
		if encoding == "identity" {
			break
		}
		if encoding != "chunked" {
			return nil, &badStringError{"unsupported transfer encoding", encoding}
		}
		te = te[0 : len(te)+1]
		te[len(te)-1] = encoding
	}

	// 只能设置一个
	if len(te) > 1 {
		return nil, &badStringError{"too many transfer encodings", strings.Join(te, ",")}
	}
	if len(te) > 0 {
		// RFC 7230 3.3.2 says "A sender MUST NOT send a
		// Content-Length header field in any message that
		// contains a Transfer-Encoding header field."
		//
		// but also:
		// "If a message is received with both a
		// Transfer-Encoding and a Content-Length header
		// field, the Transfer-Encoding overrides the
		// Content-Length. Such a message might indicate an
		// attempt to perform request smuggling (Section 9.5)
		// or response splitting (Section 9.4) and ought to be
		// handled as an error. A sender MUST remove the
		// received Content-Length field prior to forwarding
		// such a message downstream."
		//
		// Reportedly, these appear in the wild.
		// RFC 7230 3.3.2说:“发送方绝对不能在任何包含Transfer-Encoding报头字段的消息中发送Content-Length报头字段。”
		delete(header, "Content-Length")
		return te, nil
	}

	return nil, nil
}

// Determine the expected body length, using RFC 2616 Section 4.4. This
// function is not a method, because ultimately it should be shared by
// ReadResponse and ReadRequest.
// 使用RFC 2616 Section 4.4确定预期的体长。这个函数不是一个方法，因为最终它应该被ReadResponse和ReadRequest共享。
// https://blog.csdn.net/Auuuuuuuu/article/details/108112724 请求走私
func fixLength(isResponse bool, status int, requestMethod string, header Header, te []string) (int64, error) {
	isRequest := !isResponse
	contentLens := header["Content-Length"]

	// Hardening against HTTP request smuggling
	// 防止请走走私
	if len(contentLens) > 1 {
		// Per RFC 7230 Section 3.3.2, prevent multiple
		// Content-Length headers if they differ in value.
		// If there are dups of the value, remove the dups.
		// See Issue 16490.
		// Content-Length 有多个值并且都不相等就报错
		first := textproto.TrimString(contentLens[0])
		for _, ct := range contentLens[1:] {
			if first != textproto.TrimString(ct) {
				return 0, fmt.Errorf("http: message cannot contain multiple Content-Length headers; got %q", contentLens)
			}
		}

		// deduplicate Content-Length
		// 删除现有的Content-Length，重新设置
		header.Del("Content-Length")
		header.Add("Content-Length", first)

		contentLens = header["Content-Length"]
	}

	// Logic based on response type or status
	// 基于响应类型或状态的逻辑
	if noBodyExpected(requestMethod) {
		// For HTTP requests, as part of hardening against request
		// smuggling (RFC 7230), don't allow a Content-Length header for
		// methods which don't permit bodies. As an exception, allow
		// exactly one Content-Length header if its value is "0".
		// 对于HTTP请求，作为加固请求走私(RFC 7230)的一部分，不允许对不允许body的方法使用Content-Length头。
		// 作为例外，如果其值为“0”，则只允许一个Content-Length头。
		if isRequest && len(contentLens) > 0 && !(len(contentLens) == 1 && contentLens[0] == "0") {
			return 0, fmt.Errorf("http: method cannot contain a Content-Length; got %q", contentLens)
		}
		return 0, nil
	}

	// 1XX 表示临时响应并需要请求者继续执行操作的状态代码。
	if status/100 == 1 {
		return 0, nil
	}

	// StatusNoContent 服务器成功处理了请求，但没有返回任何内容。
	// StatusNotModified 自从上次请求后，请求的网页未修改过。 服务器返回此响应时，不会返回网页内容。
	switch status {
	case StatusNoContent, StatusNotModified:
		return 0, nil
	}

	// Logic based on Transfer-Encoding
	// 基于传输编码的逻辑，length返回-1
	if chunked(te) {
		return -1, nil
	}

	// Logic based on Content-Length
	// 基于内容长度的逻辑
	var cl string
	if len(contentLens) == 1 {
		cl = textproto.TrimString(contentLens[0])
	}
	if cl != "" {
		n, err := parseContentLength(cl)
		if err != nil {
			return -1, err
		}
		return n, nil
	} else {
		header.Del("Content-Length") // 没设置Content-Length值
	}

	// 未设置Content-Length
	if !isResponse {
		// RFC 2616 neither explicitly permits nor forbids an
		// entity-body on a GET request so we permit one if
		// declared, but we default to 0 here (not -1 below)
		// if there's no mention of a body.
		// Likewise, all other request methods are assumed to have
		// no body if neither Transfer-Encoding chunked nor a
		// Content-Length are set.
		// RFC 2616既不显式允许也不禁止在GET请求中使用body，所以如果声明了，我们允许使用，但是如果没有提到body，我们默认为0(而不是-1)。
		// 同样地，如果没有设置Transfer-Encoding chunked或Content-Length，则假定所有其他请求方法都没有body。
		return 0, nil
	}

	// Body-EOF logic based on other methods (like closing, or chunked coding)
	// 基于其他方法(如关闭，或分块编码)的Body-EOF逻辑
	return -1, nil
}

// Determine whether to hang up after sending a request and body, or
// receiving a response and body
// 'header' is the request headers
func shouldClose(major, minor int, header Header) bool {
	if major < 1 {
		return true
	} else if major == 1 && minor == 0 {
		return !strings.Contains(strings.ToLower(header.GetDirect("Connection")), "keep-alive")
	} else {
		// TODO: Should split on commas, toss surrounding white space,
		// and check each field.
		if strings.ToLower(header.GetDirect("Connection")) == "close" {
			header.Del("Connection")
			return true
		}
	}
	return false
}

// Parse the trailer header
// 解析并校验trailer
func fixTrailer(header Header, te []string) (Header, error) {
	raw := header.GetDirect("Trailer")
	if raw == "" {
		return nil, nil
	}

	header.Del("Trailer") // 从head中删除
	trailer := make(Header)
	keys := strings.Split(raw, ",")
	for _, key := range keys {
		key = CanonicalHeaderKey(strings.TrimSpace(key))
		switch key {
		case "Transfer-Encoding", "Trailer", "Content-Length":
			return nil, &badStringError{"bad trailer key", key}
		}
		trailer.Del(key) // todo
	}
	if len(trailer) == 0 {
		return nil, nil
	}
	if !chunked(te) {
		// Trailer and no chunking
		return nil, ErrUnexpectedTrailer
	}
	return trailer, nil
}

// body turns a Reader into a ReadCloser.
// Close ensures that the body has been fully read
// and then reads the trailer if necessary.
// body将Reader转换为ReadCloser。
// 关闭确保主体已经被完全读取，然后在必要时读取预告片。
type body struct {
	src     io.Reader
	hdr     interface{}       // non-nil (Response or Request) value means read trailer
	r       *bfe_bufio.Reader // underlying wire-format reader for the trailer
	closing bool              // is the connection to be closed after reading body?

	mu     sync.Mutex // guards closed, and calls to Read and Close
	closed bool
}

// ErrBodyReadAfterClose is returned when reading a Request or Response
// Body after the body has been closed. This typically happens when the body is
// read after an HTTP Handler calls WriteHeader or Write on its
// ResponseWriter.
var ErrBodyReadAfterClose = errors.New("http: invalid Read on closed Body")

func (b *body) Read(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, ErrBodyReadAfterClose
	}
	return b.readLocked(p)
}

// Must hold b.mu.
func (b *body) readLocked(p []byte) (n int, err error) {
	n, err = b.src.Read(p)

	if err == io.EOF {
		// Chunked case. Read the trailer.
		if b.hdr != nil {
			if e := b.readTrailer(); e != nil {
				err = e
			}
			b.hdr = nil
		} else {
			// If the server declared the Content-Length, our body is a LimitedReader
			// and we need to check whether this EOF arrived early.
			if lr, ok := b.src.(*io.LimitedReader); ok && lr.N > 0 {
				err = io.ErrUnexpectedEOF
			}
		}
	}

	return n, err
}

var (
	singleCRLF = []byte("\r\n")
	doubleCRLF = []byte("\r\n\r\n")
)

func seeUpcomingDoubleCRLF(r *bfe_bufio.Reader) bool {
	for peekSize := 4; ; peekSize++ {
		// This loop stops when Peek returns an error,
		// which it does when r's buffer has been filled.
		buf, err := r.Peek(peekSize)
		if bytes.HasSuffix(buf, doubleCRLF) {
			return true
		}
		if err != nil {
			break
		}
	}
	return false
}

var errTrailerEOF = errors.New("http: unexpected EOF reading trailer")

func (b *body) readTrailer() error {
	// The common case, since nobody uses trailers.
	buf, err := b.r.Peek(2)
	if bytes.Equal(buf, singleCRLF) {
		b.r.ReadByte()
		b.r.ReadByte()
		return nil
	}
	if len(buf) < 2 {
		return errTrailerEOF
	}
	if err != nil {
		return err
	}

	// Make sure there's a header terminator coming up, to prevent
	// a DoS with an unbounded size Trailer.  It's not easy to
	// slip in a LimitReader here, as textproto.NewReader requires
	// a concrete *bufio.Reader.  Also, we can't get all the way
	// back up to our conn's LimitedReader that *might* be backing
	// this bufio.Reader.  Instead, a hack: we iteratively Peek up
	// to the bufio.Reader's max size, looking for a double CRLF.
	// This limits the trailer to the underlying buffer size, typically 4kB.
	if !seeUpcomingDoubleCRLF(b.r) {
		return errors.New("http: suspiciously long trailer after chunked body")
	}

	hdr, err := textproto.NewReader(b.r).ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			return errTrailerEOF
		}
		return err
	}
	switch rr := b.hdr.(type) {
	case *Request:
		rr.Trailer = Header(hdr)
	case *Response:
		rr.Trailer = Header(hdr)
	}
	return nil
}

// note: add peek function for waf to process body
// peek from underlying buf reader
func (b *body) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b *body) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	var err error
	switch {
	case b.hdr == nil && b.closing:
		// no trailer and closing the connection next.
		// no point in reading to EOF.
	default:
		// Fully consume the body, which will also lead to us reading
		// the trailer headers after the body, if present.
		_, err = io.Copy(ioutil.Discard, bodyLocked{b})
	}
	b.closed = true
	return err
}

// bodyLocked is a io.Reader reading from a *body when its mutex is
// already held.
type bodyLocked struct {
	b *body
}

func (bl bodyLocked) Read(p []byte) (n int, err error) {
	if bl.b.closed {
		return 0, ErrBodyReadAfterClose
	}
	return bl.b.readLocked(p)
}

// parseContentLength trims whitespace from s and returns -1 if no value
// is set, or the value if it's >= 0.
// 从s中删除空格，如果没有设置值则返回-1，如果是>= 0则返回值。
func parseContentLength(cl string) (int64, error) {
	cl = strings.TrimSpace(cl)
	if cl == "" {
		return -1, nil
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 {
		return 0, &badStringError{"bad Content-Length", cl}
	}
	return n, nil

}
