//go:build linux && amd64

package core

import (
	"net"
	"syscall"

	"github.com/guno1928/alosmap"
)

// ListenAndServeQUIC starts the HTTP/3 server over QUIC, listening for UDP
// packets on the configured address (default ":443") using the epoll-based
// receive path. It blocks until the server is shut down.
func (s *Server) ListenAndServeQUIC() error {
	if err := s.ensureStartInit(); err != nil {
		return err
	}
	s.ensureTLSRuntime()

	addr := s.config.Addr
	if addr == "" {
		addr = ":443"
	}

	numListeners := s.config.Listeners
	if numListeners <= 0 {
		numListeners = 1
	}

	s.logger().Info("HTTP/3 listening", "addr", addr, "listeners", numListeners, "backend", "epoll")

	connMap := alosmap.NewTyped[[20]byte, *QUICConn]().Prealloc(256)
	return s.listenAndServeQUICEpoll(addr, connMap)
}

func (s *Server) handleQUICPacketIOUring(uc uringUDPSender, from *syscall.RawSockaddrInet4, data []byte, pbuf *[]byte, connMap *quicConnMap) {
	if len(data) < 5 {
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}

	if quicIsLongHeader(data) {
		s.handleQUICLongPacketIOUring(uc, sockaddrToUDPAddr(from), data, pbuf, connMap)
	} else {
		s.handleQUICShortPacketIOUring(uc, from, data, pbuf, connMap)
	}
}

func (s *Server) handleQUICLongPacketIOUring(uc uringUDPSender, remoteAddr *net.UDPAddr, data []byte, pbuf *[]byte, connMap *quicConnMap) {
	hdr, _, err := quicParseLongHeader(data)
	if err != nil {
		if debugFlag.Load() {
			Dbg("[H3-DBG] handleLongPacket: parse error: %v (dataLen=%d)", err, len(data))
		}
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}

	if debugFlag.Load() {
		Dbg("[H3-DBG] handleLongPacket: type=%d ver=0x%08x dcid=%x scid=%x from %s",
			hdr.pktType, hdr.version, hdr.dcid, hdr.scid, remoteAddr)
	}

	if hdr.version != quicVersion1 {
		if debugFlag.Load() {
			Dbg("[H3-DBG] handleLongPacket: unsupported version 0x%08x", hdr.version)
		}
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}

	dcidKey := quicCIDKey(hdr.dcid)

	if hdr.pktType == quicPktInitial {
		var qc *QUICConn
		if v, exists := connMap.Load(dcidKey); exists {
			qc = v
			if debugFlag.Load() {
				Dbg("[H3-DBG] handleLongPacket: existing conn for dcid=%x", hdr.dcid)
			}
		}
		if len(data) < quicMinInitialDatagram {
			if pbuf != nil {
				quicRecvBufPool.Put(pbuf)
			}
			return
		}
		if qc == nil {
			if debugFlag.Load() {
				Dbg("[H3-DBG] handleLongPacket: NEW Initial from %s, creating conn", remoteAddr)
			}
			admission := s.admitInitial(&hdr, remoteAddr.AddrPort())
			if !admission.create {
				if admission.reply != nil {
					uc.sendTo(admission.reply, remoteAddr)
				}
				if pbuf != nil {
					quicRecvBufPool.Put(pbuf)
				}
				return
			}
			qc = s.createQUICConnIOUring(uc, remoteAddr, hdr.dcid, hdr.scid, connMap)
			if qc == nil {
				if debugFlag.Load() {
					Dbg("[H3-DBG] handleLongPacket: createQUICConnIOUring returned nil!")
				}
				if refusal := quicBuildInitialClose(hdr.dcid, hdr.scid, quicErrConnectionRefused); refusal != nil {
					uc.sendTo(refusal, remoteAddr)
				}
				if pbuf != nil {
					quicRecvBufPool.Put(pbuf)
				}
				return
			}
			qc.applyAdmission(admission)
		}
		qc.handlePacketPooled(data, pbuf)
		return
	}

	if qc, exists := connMap.Load(dcidKey); exists {
		if debugFlag.Load() {
			Dbg("[H3-DBG] handleLongPacket: forwarding type=%d to existing conn", hdr.pktType)
		}
		qc.handlePacketPooled(data, pbuf)
	} else {
		if debugFlag.Load() {
			Dbg("[H3-DBG] handleLongPacket: no conn found for dcid=%x type=%d", hdr.dcid, hdr.pktType)
		}
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
	}
}

func (s *Server) handleQUICShortPacketIOUring(uc uringUDPSender, from *syscall.RawSockaddrInet4, data []byte, pbuf *[]byte, connMap *quicConnMap) {
	if len(data) < 1+quicConnIDLen {
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}
	dcid := data[1 : 1+quicConnIDLen]
	dcidKey := quicCIDKey(dcid)

	qc, exists := connMap.Load(dcidKey)
	if !exists {
		if reset := s.statelessResetFor(data); reset != nil {
			uc.sendTo(reset, sockaddrToUDPAddr(from))
		}
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}
	qc.handlePacketFromPooled(data, pbuf, sockaddrToAddrPort(from))
}

func newQUICConnIOUring(server *Server, uc uringUDPSender, remoteAddr *net.UDPAddr, dcid, scid []byte) *QUICConn {
	qc := newQUICConn(server, nil, remoteAddr, dcid, scid)
	qc.udpAddr = remoteAddr
	qc.uringUDP = uc
	return qc
}

func (s *Server) admitQUICConn(remoteAddr *net.UDPAddr) (ipKey string, ok bool) {
	limits := s.limits.Load()
	if limiter := s.perIPConnLimiter.Load(); limiter != nil && limits.MaxConnsPerIP > 0 && !s.trustedProxies.active {
		ipKey = extractIP(remoteAddr.String())
		if !limiter.acquire(ipKey, limits.MaxConnsPerIP) {
			return "", false
		}
	}
	if !tryAcquireQUICHandshakeSlot(limits) {
		s.releaseQUICConnIP(ipKey)
		return "", false
	}
	if !s.tryTrackConn() {
		quicHandshakingConns.Add(-1)
		s.releaseQUICConnIP(ipKey)
		return "", false
	}
	return ipKey, true
}

func (s *Server) releaseQUICConnIP(ipKey string) {
	if ipKey != "" {
		s.perIPConnLimiter.Load().release(ipKey)
	}
}

func (s *Server) createQUICConnIOUring(uc uringUDPSender, remoteAddr *net.UDPAddr, dcid, scid []byte, connMap *quicConnMap) *QUICConn {
	ipKey, admitted := s.admitQUICConn(remoteAddr)
	if !admitted {
		return nil
	}
	clientKeys, serverKeys, err := quicDeriveInitialKeys(dcid)
	if err != nil {
		quicHandshakingConns.Add(-1)
		s.releaseTrackedConn()
		s.releaseQUICConnIP(ipKey)
		if debugFlag.Load() {
			Dbg("[QUIC] derive initial keys: %v", err)
		}
		return nil
	}

	qc := newQUICConnIOUring(s, uc, remoteAddr, dcid, scid)
	qc.handshakeCounted.Store(true)
	qc.connMap = connMap
	qc.keys[quicSpaceInitial] = clientKeys
	qc.sendKeys[quicSpaceInitial] = serverKeys

	qc.tlsState = newQuicTLSState()

	dcidKey := quicCIDKey(dcid)
	connMap.Store(dcidKey, qc)
	srcCIDKey := quicCIDKey(qc.srcCID())
	connMap.Store(srcCIDKey, qc)

	go qc.recvLoop()
	s.quicTimers.add(qc, s.done)

	quicActiveConns.Add(1)
	Stats.ActiveConns.Add(1)
	Stats.TotalConns.Add(1)
	if debugFlag.Load() {
		Dbg("[QUIC] new io_uring connection from %s dcid=%x scid=%x tlsState=%v keys=%v",
			remoteAddr, dcid, qc.srcCID(), qc.tlsState != nil, qc.keys[quicSpaceInitial] != nil)
	}

	origKey := quicCIDKey(qc.getOrigDstCID())
	go func() {
		<-qc.done
		quicActiveConns.Add(-1)
		Stats.ActiveConns.Add(-1)
		s.releaseTrackedConn()
		s.releaseQUICConnIP(ipKey)
		qc.clearHandshaking()
		connMap.Delete(dcidKey)
		connMap.Delete(srcCIDKey)
		qc.unregisterIssuedCIDs(connMap)
		if origKey != dcidKey {
			connMap.Delete(origKey)
		}
	}()

	return qc
}
