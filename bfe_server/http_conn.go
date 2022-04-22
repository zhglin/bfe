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

// HTTP server.  See RFC 2616.

package bfe_server

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

import (
	"github.com/baidu/go-lib/gotrack"
	"github.com/baidu/go-lib/log"
)

import (
	"github.com/bfenetworks/bfe/bfe_basic"
	"github.com/bfenetworks/bfe/bfe_bufio"
	"github.com/bfenetworks/bfe/bfe_http"
	"github.com/bfenetworks/bfe/bfe_module"
	"github.com/bfenetworks/bfe/bfe_tls"
	"github.com/bfenetworks/bfe/bfe_util"
	"github.com/bfenetworks/bfe/bfe_websocket"
)

// This should be >= 512 bytes for DetectContentType,
// but otherwise it's somewhat arbitrary.
const bufferBeforeChunkingSize = 512

// Actions to do with current connection.
const (
	// Reuse the connection (default aciton)
	keepAlive = iota
	// Close the connection after send response to client.
	closeAfterReply
	// Close the connection directly, do not send any data,
	// it usually means some attacks may happened.
	closeDirectly
)

var errTooLarge = errors.New("http: request too large")

// A switchReader can have its Reader changed at runtime.
// It's not safe for concurrent Reads and switches.
// switchReader可以在运行时修改它的Reader。
// 对于并发读和交换来说是不安全的。
type switchReader struct {
	io.Reader
}

// A liveSwitchReader is a switchReader that's safe for concurrent
// reads and switches, if its mutex is held.
// 一个liveSwitchReader是一个switchReader，如果它的互斥对象被持有，那么对于并发读取和交换机来说是安全的。
type liveSwitchReader struct {
	sync.Mutex
	r io.Reader
}

func (sr *liveSwitchReader) Read(p []byte) (n int, err error) {
	sr.Lock()
	r := sr.r
	sr.Unlock()
	return r.Read(p)
}

// conn represents the server side of an HTTP/HTTPS connection.
// 表示HTTP/HTTPS连接的服务器端。
type conn struct {
	// immutable: 不可变的

	// 远端网络地址 客户端地址
	remoteAddr string // network address of remote side
	// 连接到达的服务器
	server *BfeServer // the Server on which the connection arrived
	// 原始链接
	rwc net.Conn // i/o connection
	// 关于维护连接信息
	session *bfe_basic.Session // for maintain connection information

	// for http/https:

	// LimitReader从哪里读取;通常rwc
	sr liveSwitchReader // where the LimitReader reads from; usually the rwc
	// 从rwc读取，但限制可以读取的数据的量为最多N字节，每次调用Read方法都会更新N以标记剩余可以读取的字节数。
	lr *io.LimitedReader // io.LimitReader(sr)
	// 具有缓冲的读写
	buf *bfe_bufio.ReadWriter // buffered(lr,rwc), reading from bufio->limitReader->sr->rwc
	// 到达此连接的请求数
	reqSN uint32 //number of requests arrived on this connection

	mu           sync.Mutex // guards the following
	clientGone   bool       // if client has disconnected mid-request
	closeNotifyc chan bool  // made lazily
}

func (c *conn) closeNotify() <-chan bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeNotifyc == nil {
		c.closeNotifyc = make(chan bool, 1)

		pr, pw := io.Pipe()

		readSource := c.sr.r
		c.sr.Lock()
		c.sr.r = pr
		c.sr.Unlock()
		go func() {
			_, err := io.Copy(pw, readSource)
			if err == nil {
				err = io.EOF
			}
			pw.CloseWithError(err)
			c.noteClientGone()
		}()
	}
	return c.closeNotifyc
}

func (c *conn) noteClientGone() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeNotifyc != nil && !c.clientGone {
		c.closeNotifyc <- true
	}
	c.clientGone = true
}

// noLimit is an effective infinite upper bound for io.LimitedReader
// 是io.LimitedReader的有效无限上界。LimitedReader
const noLimit int64 = (1 << 63) - 1

// Create new connection from rwc.
// 创建新的链接 这里的rwc为bfe_tls.Conn, bfe_proxy.Conn，net.Conn
// https rwc = bfe_tls.Conn
// proxy rwc = bfe_proxy.Conn
// 其他   rwc = net.Conn
func newConn(rwc net.Conn, srv *BfeServer) (c *conn, err error) {
	c = new(conn)
	c.remoteAddr = rwc.RemoteAddr().String()
	c.server = srv
	c.rwc = rwc
	c.sr = liveSwitchReader{r: c.rwc}
	c.lr = io.LimitReader(&c.sr, noLimit).(*io.LimitedReader)
	// 基于lr的读缓冲
	br := srv.BufioCache.newBufioReader(c.lr)
	// 基于rwc的写缓冲
	bw := srv.BufioCache.newBufioWriterSize(c.rwc, 4<<10)
	c.buf = bfe_bufio.NewReadWriter(br, bw)
	c.reqSN = 0

	// 创建会话
	c.session = bfe_basic.NewSession(rwc)
	vip, vport, err := bfe_util.GetVipPort(rwc)
	if err == nil {
		c.session.Vip = vip
		c.session.Vport = vport

		// get product if vip -> product table is set
		sf := srv.GetServerConf()
		product, err := sf.HostTable.LookupProductByVip(vip.String())
		if err == nil {
			c.session.Product = product
		}

		log.Logger.Debug("newConn(): VIP: %v, Port: %v, Product: %v", c.session.Vip.String(), vport, product)
	} else {
		log.Logger.Debug("newConn(): GetVip: %s", err.Error())
	}

	if sc, ok := rwc.(*bfe_tls.Conn); ok {
		c.session.IsSecure = true
		sc.SetConnParam(c.session)
	}

	return c, nil
}

// Read next request from connection.
// 读取连接的下一个请求。
func (c *conn) readRequest() (request *bfe_basic.Request, err error) {
	c.lr.N = int64(c.server.MaxHeaderBytes) + 4096 /* bufio slop */

	var req *bfe_http.Request

	// another request arrives
	// 另一个请求到达
	c.reqSN += 1
	if req, err = bfe_http.ReadRequest(c.buf.Reader, c.server.MaxHeaderUriBytes); err != nil {
		if c.lr.N == 0 {
			return nil, errTooLarge
		}
		return nil, err
	}
	c.lr.N = noLimit

	req.RemoteAddr = c.remoteAddr
	req.State.SerialNumber = c.reqSN
	req.State.Conn = c.rwc

	reqStat := bfe_basic.NewRequestStat(req.State.StartTime)
	reqStat.ReadReqEnd = time.Now()
	reqStat.HeaderLenIn = int(req.State.HeaderSize)

	sf := c.server.GetServerConf()

	return bfe_basic.NewRequest(req, c.rwc, reqStat, c.session, sf), nil
}

// 写入缓冲区
func (c *conn) finalFlush() {
	if c.buf != nil {
		c.buf.Flush()

		// Steal the bufio.Writer (~4KB worth of memory) and its associated
		// writer for a future connection.
		c.server.BufioCache.putBufioWriter(c.buf.Writer)

		// Warn: it's not safe to reuse c.buf.Reader which is used by both conn
		// goroutine and transport.WriteLoop goroutine.
		// There is no guarantee that transport.WriteLoop has stopped to read from
		// c.buf.Reader when conn goroutine call finalFlush().

		c.buf = nil
	}
}

// Close the connection.
// 关闭连接。
func (c *conn) close() {
	c.finalFlush()
	c.rwc.Close()
}

// rstAvoidanceDelay is the amount of time we sleep after closing the
// write side of a TCP connection before closing the entire socket.
// By sleeping, we increase the chances that the client sees our FIN
// and processes its final data before they process the subsequent RST
// from closing a connection with known unread data.
// This RST seems to occur mostly on BSD systems. (And Windows?)
// This timeout is somewhat arbitrary (~latency around the planet).
const rstAvoidanceDelay = 500 * time.Millisecond

// closeWrite flushes any outstanding data and sends a FIN packet (if
// client is connected via TCP), signalling that we're done.  We then
// pause for a bit, hoping the client processes it before `any
// subsequent RST.
//
// See http://golang.org/issue/3595
// // closeWrite会刷新所有未完成的数据，并发送一个FIN包(如果客户端是通过TCP连接的)，表示我们完成了。然后我们暂停一会儿，希望客户端在任何后续的RST之前处理它。
func (c *conn) closeWriteAndWait() {
	c.finalFlush()
	if cw, ok := c.rwc.(bfe_util.CloseWriter); ok {
		cw.CloseWrite()
	}
	time.Sleep(rstAvoidanceDelay)
}

// callback of finish connection
// 链接处理完成的回调
func (c *conn) finish() {
	srv := c.server

	// finish session
	// 会话结束
	c.session.Finish()

	// Callback for HandleFinish
	// 回调
	hl := srv.CallBacks.GetHandlerList(bfe_module.HandleFinish)
	if hl != nil {
		hl.FilterFinish(c.session)
	}
}

func (c *conn) getMandatoryProtocol(tlsConn *bfe_tls.Conn) (string, bool) {
	tlsRule := c.server.TLSServerRule.Get(tlsConn)
	protoConf := tlsRule.NextProtos.(*NextProtosConf)
	return protoConf.Mandatory(tlsConn)
}

// Serve a new connection.
// 服务一个新的连接。
func (c *conn) serve() {
	var hl *bfe_module.HandlerList
	var retVal int
	// 会话
	session := c.session
	// 增加wait
	c.server.connWaitGroup.Add(1)
	// 状态
	serverStatus := c.server.serverStatus
	proxyState := serverStatus.ProxyState

	defer func() {
		if err := recover(); err != nil {
			log.Logger.Warn("panic: conn.serve(): %v, readTotal=%d,writeTotal=%d,reqNum=%d,%v\n%s",
				c.remoteAddr,
				c.session.ReadTotal(), c.session.WriteTotal(),
				c.session.ReqNum(),
				err, gotrack.CurrentStackTrace(0))

			proxyState.PanicClientConnServe.Inc(1)
		}

		// 减少wait计数
		c.server.connWaitGroup.Done()
	}()

	defer func() {
		// callback of finish connection
		c.finish()
		c.close()

		if len(session.Proto) > 0 {
			proxyState.ClientConnActiveDec(session.Proto, 1)
		}
		if session.ReqNumActive() != 0 {
			proxyState.ClientConnUnfinishedReq.Inc(1)
		}
	}()

	// Callback for HANDLE_ACCEPT
	// 查找并执行accept的回调
	hl = c.server.CallBacks.GetHandlerList(bfe_module.HandleAccept)
	if hl != nil {
		retVal = hl.FilterAccept(c.session)
		if retVal == bfe_module.BfeHandlerClose { // 被模块拒绝链接
			// close the connection
			return
		}
	}

	if tlsConn, ok := c.rwc.(*bfe_tls.Conn); ok {
		proxyState.TlsHandshakeAll.Inc(1)
		var d time.Duration
		// set tls handshake timeout
		if d = c.server.TlsHandshakeTimeout; d != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(d))
		}

		// start tls handshake
		start := time.Now()
		if err := tlsConn.Handshake(); err != nil {
			log.Logger.Info("conn.serve(): Handshake error %s (remote %s, vip %s), elapse %d us",
				err, c.remoteAddr, session.Vip, time.Since(start).Nanoseconds()/1000)
			session.SetError(bfe_basic.ErrClientTlsHandshake, err.Error())
			return
		}
		c.rwc.SetReadDeadline(time.Time{})
		tlsState := tlsConn.ConnectionState()
		c.session.TlsState = &tlsState

		log.Logger.Debug("conn.serve(): Handshake success (remote %s, vip %s, resume %v), elapse %d us",
			c.remoteAddr, session.Vip, tlsState.DidResume, time.Since(start).Nanoseconds()/1000)
		proxyState.TlsHandshakeSucc.Inc(1)
		serverStatus.ProxyHandshakeDelay.AddDuration(tlsState.HandshakeTime)
		if tlsState.DidResume {
			serverStatus.ProxyHandshakeResumeDelay.AddDuration(tlsState.HandshakeTime)
		} else {
			serverStatus.ProxyHandshakeFullDelay.AddDuration(tlsState.HandshakeTime)
		}

		// Callback for HANDLE_HANDSHAKE
		hl = c.server.CallBacks.GetHandlerList(bfe_module.HandleHandshake)
		if hl != nil {
			retVal = hl.FilterAccept(c.session)
			if retVal == bfe_module.BfeHandlerClose {
				// close the connection
				return
			}
		}

		// upgrade to negotiated protocol
		proto := tlsState.NegotiatedProtocol
		if mandatoryProtocol, ok := c.getMandatoryProtocol(tlsConn); ok {
			// Note: if mandatory protocol configured, use it anyway
			proto = mandatoryProtocol
		}
		if validNPN(proto) {
			if fn := c.server.TLSNextProto[proto]; fn != nil {
				log.Logger.Debug("conn.serve(): Use negotiated protocol %s over TLS", proto)
				proxyState.ClientConnServedInc(proto, 1) // Note: counter for negotiated protocol
				proxyState.ClientConnActiveInc(proto, 1)
				c.session.Proto = proto

				// process protocol over TLS connection (spdy, http2, etc)
				handler := NewProtocolHandler(c, proto)
				fn(&c.server.Server, tlsConn, handler)
			} else {
				// never go here
				log.Logger.Info("conn.serve(): unknown negotiated protocol %s over TLS", proto)
			}
			return
		}
	}

	// process requests from http/https protocol
	// 处理http/https协议的请求
	if _, ok := c.rwc.(*bfe_tls.Conn); ok {
		c.session.Proto = "https"
	} else {
		c.session.Proto = "http"
	}

	// 统计计数
	proxyState.ClientConnServedInc(c.session.Proto, 1) // Note: counter for http/https protocol
	proxyState.ClientConnActiveInc(c.session.Proto, 1)

	// 循环一直读取请求
	firstRequest := true
	for {
		if firstRequest {
			// set timeout only for first request
			// following request's timeout is controlled by TimeoutReadClientAgain
			// the read again timeout is different for each cluster
			// so it's not set here, see reverseproxy.go
			// 设置第一个请求的超时是由timeoutreadclient控制的，再次读取超时对于每个集群是不同的，所以它不在这里设置，参见reverseproxy.go
			if d := c.server.ReadTimeout; d != 0 {
				c.rwc.SetReadDeadline(time.Now().Add(d))
			}
		}

		// 读取http报文
		request, err := c.readRequest()
		if err != nil {
			if err == errTooLarge {
				session.SetError(bfe_basic.ErrClientLongHeader, "request entity too large")
				proxyState.ErrClientLongHeader.Inc(1)
				// Their HTTP client may or may not be
				// able to read this if we're
				// responding to them and hanging up
				// while they're still writing their
				// request.  Undefined behavior.
				io.WriteString(c.rwc, "HTTP/1.1 413 Request Entity Too Large\r\n\r\n")
				c.closeWriteAndWait()
				break
			} else if strings.Contains(err.Error(), "exceed maxUriBytes") {
				session.SetError(bfe_basic.ErrClientLongUrl, err.Error())
				proxyState.ErrClientLongUrl.Inc(1)
				io.WriteString(c.rwc, "HTTP/1.1 414 Request-URI Too Long\r\n\r\n")
				break
			} else if err == io.EOF {
				session.SetError(bfe_basic.ErrClientClose, err.Error())
				proxyState.ErrClientClose.Inc(1)
				break // Don't reply
			} else if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				session.SetError(bfe_basic.ErrClientTimeout, err.Error())
				proxyState.ErrClientTimeout.Inc(1)
				break // Don't reply
			} else if strings.Contains(err.Error(), "connection reset by peer") {
				session.SetError(bfe_basic.ErrClientReset, err.Error())
				proxyState.ErrClientReset.Inc(1)
				break
			}

			session.SetError(bfe_basic.ErrClientBadRequest, err.Error())
			proxyState.ErrClientBadRequest.Inc(1)
			io.WriteString(c.rwc, "HTTP/1.1 400 Bad Request\r\n\r\n")
			break
		}

		// 原始request
		req := request.HttpRequest

		// create context for response
		w := newResponse(c, req)

		// Expect 100 Continue support 支持100-continue协议
		if req.ExpectsContinue() {
			session.Use100Continue = true
			proxyState.ClientConnUse100Continue.Inc(1)

			// 校验协议版本是否支持
			if req.ProtoAtLeast(1, 1) {
				// Wrap the Body reader with one that replies on the connection
				// 将Body阅读器包装为对连接进行回复的阅读器
				req.Body = &expectContinueReader{readCloser: req.Body, resp: w}
				w.canWriteContinue.setTrue()
			}
			if req.ContentLength == 0 {
				session.SetError(bfe_basic.ErrClientZeroContentlen, "content length is zero")
				proxyState.ErrClientZeroContentlen.Inc(1)

				w.Header().Set("Connection", "close")
				w.WriteHeader(bfe_http.StatusBadRequest)
				w.finishRequest()
				break
			}
			req.Header.Del("Expect")
		} else if req.Header.GetDirect("Expect") != "" { // expect != 100-continue
			session.SetError(bfe_basic.ErrClientExpectFail, "invalid Expect header")
			proxyState.ErrClientExpectFail.Inc(1)

			w.sendExpectationFailed()
			break
		}

		// check whether client request for http upgrade (over http/https conn)
		if firstRequest {
			nextProto := checkHttpUpgrade(request)
			fn := c.server.HTTPNextProto[nextProto]

			switch nextProto {
			case bfe_websocket.WebSocket:
				// update counters for websocket
				proxyState.ClientConnActiveDec(c.session.Proto, 1)
				c.session.Proto = bfe_websocket.Scheme(c.rwc)
				proxyState.ClientConnServedInc(c.session.Proto, 1)
				proxyState.ClientConnActiveInc(c.session.Proto, 1)

				// Note: The runtime will not GC the objects referenced by request.SvrDataConf until the websocket connection
				// has been processed. But the connection may last a long time. It's better to remove the reference to objects
				// which are not used any more.
				request.SvrDataConf = nil

				// switching to websocket protocol
				log.Logger.Debug("conn.serve(): upgrade to websocket protocol over http/https")
				fn(&c.server.Server, w, req)
				return
			default:
				log.Logger.Debug("conn.serve(): not upgrade to other protocol over http/https")
			}
			firstRequest = false
		}

		isKeepAlive := c.serveRequest(w, request)

		/* close connection if needed:
		 * - server-level close (closeAfterReply):
		 *   connection blocked, request processed error, etc
		 *
		 * - http-level close (w.closeAfterReply):
		 *   proto version < 1.1, request or response with header "connection: close",
		 *   keepalive disabled, etc
		 */
		if !isKeepAlive || w.closeAfterReply {
			if w.requestBodyLimitHit {
				c.closeWriteAndWait()
			}
			break
		}
	}
}

func (c *conn) serveRequest(w bfe_http.ResponseWriter, request *bfe_basic.Request) (isKeepAlive bool) {
	session := c.session
	serverStatus := c.server.serverStatus
	proxyState := serverStatus.ProxyState

	session.IncReqNum(1)
	session.IncReqNumActive(1)

	proxyState.ClientReqServedInc(session.Proto, 1)
	proxyState.ClientReqActiveInc(session.Proto, 1)

	// HTTP cannot have multiple simultaneous active requests.[*]
	// Until the server replies to this request, it can't read another,
	// so we might as well run the handler in this goroutine.
	// [*] Not strictly true: HTTP pipelining.  We could let them all process
	// in parallel even if their responses need to be serialized.

	// serve the request
	ret1 := c.server.ReverseProxy.ServeHTTP(w, request)

	// if there is some response, count the time
	if !request.Stat.ResponseStart.IsZero() {
		request.Stat.ResponseEnd = time.Now()
	}

	// finish process for http/https protocol
	res, ok := w.(*response)
	if ok {
		if ret1 == closeDirectly {
			res.prepareForCloseConn()
		} else {
			res.finishRequest()
		}
		if !request.Stat.ResponseStart.IsZero() {
			request.Stat.HeaderLenOut = int(res.headerWritten)
			request.Stat.BodyLenOut = res.cw.length
		}
	}

	// callback for finish request
	ret2 := c.server.ReverseProxy.FinishReq(w, request)

	// modify state counters
	session.IncReqNumActive(-1)
	proxyState.ClientReqActiveDec(session.Proto, 1)
	if request.ErrCode != nil {
		proxyState.ClientReqFail.Inc(1)
	} else {
		// only counter "internal delay" for successful request
		if !request.Stat.BackendFirst.IsZero() {
			// In redirect and some other cases, BackendFirst may be not set

			if request.HttpRequest.ContentLength == 0 {
				// for get/head request
				serverStatus.ProxyDelay.AddBySub(request.Stat.ReadReqEnd, request.Stat.BackendFirst)
			} else {
				// for post/put request
				serverStatus.ProxyPostDelay.AddBySub(request.Stat.ReadReqEnd, request.Stat.BackendFirst)
			}
		}
	}

	isKeepAlive = (ret1 == keepAlive) && (ret2 == keepAlive)
	return
}

// validNPN reports whether the proto is not a blocklisted Next
// Protocol Negotiation protocol.  Empty and built-in protocol types
// are blocklisted and can't be overridden with alternate
// implementations.
func validNPN(proto string) bool {
	switch proto {
	case "", "http/1.1", "http/1.0":
		return false
	}
	return true
}

func checkHttpUpgrade(req *bfe_basic.Request) string {
	if bfe_websocket.CheckUpgradeWebSocket(req.HttpRequest) {
		return bfe_websocket.WebSocket
	}
	return ""
}
