//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"hash"

	"github.com/guno1928/turbo"
)

type quicTLSState struct {
	hashFn         func() hash.Hash
	hashLen        int
	suite          *CipherSuiteConfig
	transcript     hash.Hash
	ch             ParsedClientHello
	clientHSSecret []byte
	stage          int

	retry           *tls13Retry
	initialConsumed int
	hsConsumed      int
	masterSecret    []byte
	clientAuth      *tls13ClientAuth
	peerChain       [][]byte
}

const (
	quicALPN          = "h3"
	quicErrCryptoBase = 0x0100
)

const (
	quicTLSStageWaitClientHello = 0
	quicTLSStageWaitFinished    = 1
	quicTLSStageDone            = 2
)

func newQuicTLSState() *quicTLSState {
	return &quicTLSState{
		stage: quicTLSStageWaitClientHello,
	}
}

func (qc *QUICConn) closeWithTLSAlert(alert tlsAlert) {
	if qc.closed.Load() {
		return
	}
	space := quicSpaceInitial
	if k := qc.sendKeys[quicSpaceHandshake]; k != nil && k.valid {
		space = quicSpaceHandshake
	}
	qc.sendFrames(space, quicAppendConnCloseFrame(nil, quicErrCryptoBase+uint64(alert), quicFrameCrypto, ""), false)
	qc.close()
}

func (ts *quicTLSState) messageStart(space int) int {
	switch space {
	case quicSpaceInitial:
		return ts.initialConsumed
	case quicSpaceHandshake:
		return ts.hsConsumed
	}
	return 0
}

func (ts *quicTLSState) negotiateKeyShare(qc *QUICConn, ch *ParsedClientHello, hello []byte) (*CipherSuiteConfig, keyShareChoice, bool) {
	if ts.retry != nil {
		share, alert, ok := ts.retry.acceptSecondHello(ch)
		if !ok {
			qc.closeWithTLSAlert(alert)
			return nil, keyShareChoice{}, false
		}
		return ts.retry.suite, keyShareChoice{group: ts.retry.group, share: share}, true
	}
	suite := negotiateQUICSuite(ch.CipherSuites)
	if suite == nil {
		qc.closeWithTLSAlert(alertHandshakeFailure)
		return nil, keyShareChoice{}, false
	}
	choice, ok := selectKeyShare(ch, qc.server.config.TLSPreferPostQuantum)
	if !ok {
		qc.closeWithTLSAlert(alertHandshakeFailure)
		return nil, keyShareChoice{}, false
	}
	if choice.retry {
		ts.sendHelloRetry(qc, suite, choice.group, ch, hello)
		return nil, keyShareChoice{}, false
	}
	return suite, choice, true
}

func (ts *quicTLSState) sendSessionTicket(qc *QUICConn) {
	if ts.masterSecret == nil {
		return
	}
	var hashBuf [64]byte
	p := newPendingTicket(ts.suite, ts.masterSecret, ts.transcript.Sum(hashBuf[:0]), ts.ch.ServerName, quicALPN, ts.peerChain)
	clear(ts.masterSecret)
	ts.masterSecret = nil
	if msg := qc.server.newSessionTicketMessage(p); msg != nil {
		qc.sendFrames(quicSpaceAppData, quicAppendCryptoFrame(nil, 0, msg), true)
	}
}

func (ts *quicTLSState) sendHelloRetry(qc *QUICConn, cs *CipherSuiteConfig, group tlsGroup, ch *ParsedClientHello, hello []byte) {
	retry, hrr := newHelloRetry(cs, group, ch, hello)
	ts.retry = retry
	ts.initialConsumed = len(hello)
	qc.firstFlight.initialOffset = uint64(len(hrr))
	qc.sendFrames(quicSpaceInitial, quicAppendCryptoFrame(nil, 0, hrr), true)
}

func (ts *quicTLSState) handleCryptoData(qc *QUICConn, space int, data []byte) {
	switch ts.stage {
	case quicTLSStageWaitClientHello:
		if space != quicSpaceInitial {
			return
		}
		qc.firstFlight.lastSent = turbo.Now()
		ts.handleClientHello(qc, data)
		if ts.stage == quicTLSStageWaitFinished {
			ts.initialConsumed += len(data)
		}
	case quicTLSStageWaitFinished:
		if space != quicSpaceHandshake {
			return
		}
		ts.hsConsumed += len(data)
		if ts.clientAuth != nil {
			ts.handleClientAuthMessage(qc, data)
			return
		}
		ts.handleClientFinished(qc, data)
	}
}

func (ts *quicTLSState) handleClientAuthMessage(qc *QUICConn, msg []byte) {
	done, alert, ok := ts.clientAuth.feed(msg)
	if !ok {
		qc.closeWithTLSAlert(alert)
		return
	}
	if !done {
		return
	}
	qc.peerCerts = ts.clientAuth.peerCerts
	ts.peerChain = ts.clientAuth.peerChain
	ts.clientAuth = nil
	ts.completeHandshake(qc)
}

func (ts *quicTLSState) handleClientHello(qc *QUICConn, data []byte) {
	if debugFlag.Load() {
		Dbg("[QUIC-DBG] handleClientHello: dataLen=%d", len(data))
	}
	if len(data) < 4 {
		if debugFlag.Load() {
			Dbg("[QUIC-DBG] handleClientHello: too short (%d < 4)", len(data))
		}
		return
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if debugFlag.Load() {
		Dbg("[QUIC-DBG] handleClientHello: msgType=0x%02x msgLen=%d totalAvail=%d", data[0], msgLen, len(data))
	}
	if len(data) < 4+msgLen {
		if debugFlag.Load() {
			Dbg("[QUIC-DBG] handleClientHello: truncated (%d < %d)", len(data), 4+msgLen)
		}
		return
	}

	ch := &ts.ch
	ch.Reset()
	if err := ParseClientHello(data, ch); err != nil {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] bad ClientHello: %v", err)
		}
		qc.closeWithTLSAlert(alertDecodeError)
		return
	}
	if !ch.quicTP.seen {
		qc.closeWithTLSAlert(quicTLSAlertMissingExtension)
		return
	}
	if ch.quicTP.invalid || !ch.quicTP.hasInitialSrcCID || !bytes.Equal(ch.quicTP.initialSrcCID, qc.dstCID()) {
		qc.closeWithError(quicErrTransportParameter, "invalid transport parameters")
		return
	}
	if len(ch.SessionID) > 0 {
		qc.closeWithError(quicErrProtocolViolation, "non-empty legacy_session_id")
		return
	}
	qc.applyPeerTransportParams(ch)
	if debugFlag.Load() {
		Dbg("[H3-TLS] ClientHello: SNI=%q TLS13=%v suites=%v x25519=%v sessionID_len=%d maxUDP=%d",
			ch.ServerName, ch.SupportsTLS13(), ch.CipherSuites, ch.X25519PubKey != nil, len(ch.SessionID), ch.MaxUDPPayload)
	}
	if debugFlag.Load() {
		Dbg("[H3-TLS] ClientHello first 20 bytes: %x", data[:min(20, len(data))])
	}
	if debugFlag.Load() {
		Dbg("[H3-TLS] ClientHello raw bytes 4-10: %x", data[4:min(10, len(data))])
	}

	if !ch.SupportsTLS13() {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] client doesn't support TLS 1.3")
		}
		qc.closeWithTLSAlert(alertProtocolVersion)
		return
	}

	if !ch.offersALPN(quicALPN) {
		qc.closeWithTLSAlert(alertNoApplicationProtocol)
		return
	}

	entry := qc.server.certStore.Lookup(ch.ServerName)
	if entry == nil {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] no cert for SNI %q", ch.ServerName)
		}
		qc.closeWithTLSAlert(certMissAlert(ch.ServerName))
		return
	}
	if debugFlag.Load() {
		Dbg("[H3-TLS] cert found for %q, privKey type=%T, chainDER=%d certs", ch.ServerName, entry.PrivKey, len(entry.ChainDER))
	}
	if entry.PrivKey == nil {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] cert for %q has no private key", ch.ServerName)
		}
		qc.closeWithTLSAlert(certMissAlert(ch.ServerName))
		return
	}

	suite, choice, ok := ts.negotiateKeyShare(qc, ch, data[:4+msgLen])
	if !ok {
		return
	}
	if debugFlag.Load() {
		Dbg("[H3-TLS] negotiated suite: 0x%04x (hash=%d) group: 0x%04x", suite.ID, suite.HashLen, uint16(choice.group))
	}
	ts.suite = suite
	ts.hashFn = suite.HashFn
	ts.hashLen = suite.HashLen
	ts.transcript = ts.hashFn()
	var retryPrefix []byte
	if ts.retry != nil {
		retryPrefix = ts.retry.transcriptPrefix
		ts.retry = nil
	}
	ts.transcript.Write(retryPrefix)

	policy := qc.server.clientAuthFor(entry)
	qc.tlsCertEntry = entry
	session, alert, ok := qc.server.acceptResumption(resumeRequest{
		ch:               ch,
		cs:               suite,
		policy:           policy,
		requiredALPN:     quicALPN,
		transcriptPrefix: retryPrefix,
		hello:            data[:4+msgLen],
	}, nil)
	if !ok {
		qc.closeWithTLSAlert(alert)
		return
	}
	resumed := session.early != nil
	hsSalt := suite.derivedFromEarly
	var resumedSaltBuf [64]byte
	if resumed {
		hsSalt = suite.DeriveSecretTo(&suite.labelDerived, session.early, suite.emptyTranscriptHash, resumedSaltBuf[:0])
		clear(session.early)
		qc.peerCerts = session.peerCerts
		ts.peerChain = session.peerChain
	}
	requestCert := policy.requests() && !resumed

	var kx serverKeyShare
	if alert, ok := qc.server.completeKeyShare(&kx, choice.group, choice.share); !ok {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] key exchange for group 0x%04x failed", uint16(choice.group))
		}
		qc.closeWithTLSAlert(alert)
		return
	}
	defer kx.wipe()

	ts.transcript.Write(data[:4+msgLen])
	chHash := make([]byte, 0, ts.hashLen)
	chHash = ts.transcript.Sum(chHash)
	if debugFlag.Load() {
		Dbg("[H3-TLS] transcript after CH: %x", chHash)
	}

	var serverRandom [32]byte
	rand.Read(serverRandom[:])
	serverHello := buildServerHelloMessage(serverHelloSpec{
		random:    serverRandom[:],
		sessionID: ch.SessionID,
		suite:     suite.ID,
		group:     uint16(choice.group),
		share:     kx.share(),
		psk:       resumed,
	})
	ts.transcript.Write(serverHello)

	chHash = chHash[:0]
	chHash = ts.transcript.Sum(chHash)
	if debugFlag.Load() {
		Dbg("[QUIC-DBG] CH+SH transcript hash: %x", chHash)
	}

	h := ts.hashFn
	handshakeSecret := kx.extractHandshakeSecret(suite, hsSalt, nil)
	clear(resumedSaltBuf[:])

	var clientHSBuf, serverHSBuf [64]byte
	clientHSSecret := suite.DeriveSecretTo(&suite.labelClientHSTraffic, handshakeSecret, chHash, clientHSBuf[:0])
	serverHSSecret := suite.DeriveSecretTo(&suite.labelServerHSTraffic, handshakeSecret, chHash, serverHSBuf[:0])

	clientHSKeys, err := quicDeriveKeys(h, clientHSSecret, suite)
	if err != nil {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] derive client HS keys: %v", err)
		}
		qc.closeWithTLSAlert(alertInternalError)
		return
	}
	serverHSKeys, err := quicDeriveKeys(h, serverHSSecret, suite)
	if err != nil {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] derive server HS keys: %v", err)
		}
		qc.closeWithTLSAlert(alertInternalError)
		return
	}

	qc.keys[quicSpaceHandshake] = clientHSKeys
	qc.sendKeys[quicSpaceHandshake] = serverHSKeys

	tp := quicBuildTransportParams(qc)
	if debugFlag.Load() {
		Dbg("[H3-TLS] transport params: %d bytes, hex=%x", len(tp), tp[:min(40, len(tp))])
	}
	ee := quicBuildEncryptedExtensions(quicALPN, tp)
	if requestCert {
		ee = append(ee, certificateRequest13...)
	}
	if debugFlag.Load() {
		Dbg("[H3-TLS] EncryptedExtensions: %d bytes, first20=%x", len(ee), ee[:min(20, len(ee))])
	}
	ts.transcript.Write(ee)
	var cert, cv []byte
	if !resumed {
		cert = entry.certificate13(entry.stapleFor(ch))
		ts.transcript.Write(cert)
		cvHash := make([]byte, 0, ts.hashLen)
		cvHash = ts.transcript.Sum(cvHash)
		cvScheme, sig, sigErr := SignCertificateVerify(entry.PrivKey, cvHash, ch.SignatureSchemes)
		if sigErr != nil {
			if debugFlag.Load() {
				Dbg("[QUIC-TLS] sign CertificateVerify: %v", sigErr)
			}
			qc.closeWithTLSAlert(signFailureAlert(sigErr))
			return
		}
		cv = BuildCertificateVerify(cvScheme, sig)
		ts.transcript.Write(cv)
	}

	finHash := make([]byte, 0, ts.hashLen)
	finHash = ts.transcript.Sum(finHash)
	finData := suite.ComputeFinishedTo(serverHSSecret, finHash, nil)
	fin := BuildFinished(finData)
	ts.transcript.Write(fin)

	if debugFlag.Load() {
		Dbg("[QUIC-DBG] HS message sizes: serverHello=%d ee=%d cert=%d cv=%d fin=%d chainDER=%d certs",
			len(serverHello), len(ee), len(cert), len(cv), len(fin), len(entry.ChainDER))
	}
	qc.sendFirstFlight(serverHello, ee, cert, cv, fin)

	ts.clientHSSecret = make([]byte, len(clientHSSecret))
	copy(ts.clientHSSecret, clientHSSecret)
	if requestCert {
		ts.clientAuth = newTLS13ClientAuth(policy, suite, ts.transcript, clientHSSecret)
	}

	var derivedFromHS [64]byte
	derivedHS := suite.DeriveSecretTo(&suite.labelDerived, handshakeSecret, suite.emptyTranscriptHash, derivedFromHS[:0])
	masterSecret := TLSExtract(h, derivedHS, suite.zeroHashInput)
	if qc.server.issuesTickets(ch) {
		ts.masterSecret = masterSecret
	}

	sfHash := make([]byte, 0, ts.hashLen)
	sfHash = ts.transcript.Sum(sfHash)
	var clientAppBuf, serverAppBuf [64]byte
	clientAppSecret := suite.DeriveSecretTo(&suite.labelClientAppTraffic, masterSecret, sfHash, clientAppBuf[:0])
	serverAppSecret := suite.DeriveSecretTo(&suite.labelServerAppTraffic, masterSecret, sfHash, serverAppBuf[:0])

	clientAppKeys, err := quicDeriveKeys(h, clientAppSecret, suite)
	if err != nil {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] derive client app keys: %v", err)
		}
		qc.closeWithTLSAlert(alertInternalError)
		return
	}
	serverAppKeys, err := quicDeriveKeys(h, serverAppSecret, suite)
	if err != nil {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] derive server app keys: %v", err)
		}
		qc.closeWithTLSAlert(alertInternalError)
		return
	}

	qc.keys[quicSpaceAppData] = clientAppKeys
	qc.sendKeys[quicSpaceAppData] = serverAppKeys

	qc.recvSecret = make([]byte, len(clientAppSecret))
	copy(qc.recvSecret, clientAppSecret)
	qc.sendSecret = make([]byte, len(serverAppSecret))
	copy(qc.sendSecret, serverAppSecret)
	qc.appSuite = suite
	qc.origHP = clientAppKeys.hp

	nextRecvSecret := quicDeriveNextTrafficSecret(suite.HashFn, clientAppSecret, suite.HashLen)
	nextRecvKeys, _ := quicDeriveKeys(suite.HashFn, nextRecvSecret, suite)
	if nextRecvKeys != nil {
		nextRecvKeys.hp = clientAppKeys.hp
		qc.nextRecvKeys = nextRecvKeys
		qc.recvSecret = nextRecvSecret
	}

	ts.stage = quicTLSStageWaitFinished

	if debugFlag.Load() {
		Dbg("[QUIC-TLS] server handshake flight sent, waiting for client Finished")
	}
}

const (
	quicTPOrigDstCID            = 0x00
	quicTPMaxIdleTimeout        = 0x01
	quicTPStatelessResetToken   = 0x02
	quicTPRetrySrcCID           = 0x10
	quicTPInitialMaxData        = 0x04
	quicTPInitialMaxStreamBidiL = 0x05
	quicTPInitialMaxStreamBidiR = 0x06
	quicTPInitialMaxStreamUni   = 0x07
	quicTPInitialMaxStreamsBidi = 0x08
	quicTPInitialMaxStreamsUni  = 0x09
	quicTPInitialSrcCID         = 0x0f
	quicTPActiveConnIDLimit     = 0x0e
)

const (
	quicTPMaxUDPPayloadSize      = 0x03
	quicTPAckDelayExponent       = 0x0a
	quicTPMaxAckDelay            = 0x0b
	quicTPDisableActiveMigration = 0x0c
	quicTPPreferredAddress       = 0x0d

	quicTPTrackedIDs            = 64
	quicMinUDPPayloadSize       = 1200
	quicDefaultAckDelayExponent = 3
	quicMaxAckDelayExponent     = 20
	quicDefaultMaxAckDelayMs    = 25
	quicMaxAckDelayLimitMs      = 1 << 14
	quicMinActiveConnIDLimit    = 2
	quicMaxStreamsLimit         = 1 << 60
	quicErrTransportParameter   = 0x08

	quicTLSAlertMissingExtension tlsAlert = 109
)

type quicPeerTransportParams struct {
	seen             bool
	invalid          bool
	hasInitialSrcCID bool
	initialSrcCID    []byte
	ackDelayExponent uint64
	maxAckDelayMs    uint64
}

func quicTPIsInteger(id uint64) bool {
	switch id {
	case quicTPMaxIdleTimeout, quicTPMaxUDPPayloadSize, quicTPInitialMaxData, quicTPInitialMaxStreamBidiL,
		quicTPInitialMaxStreamBidiR, quicTPInitialMaxStreamUni, quicTPInitialMaxStreamsBidi,
		quicTPInitialMaxStreamsUni, quicTPAckDelayExponent, quicTPMaxAckDelay, quicTPActiveConnIDLimit:
		return true
	}
	return false
}

func quicBuildTransportParams(qc *QUICConn) []byte {
	var tp []byte
	appendTP := func(id uint64, val []byte) {
		tp = quicAppendVarint(tp, id)
		tp = quicAppendVarint(tp, uint64(len(val)))
		tp = append(tp, val...)
	}
	appendTPVarint := func(id, val uint64) {
		var buf [8]byte
		n := quicPutVarint(buf[:], val)
		appendTP(id, buf[:n])
	}

	idleMs := uint64(qc.idleTimeout.Milliseconds())
	if idleMs == 0 {
		idleMs = 30000
	}
	streamData := uint64(1 << 18)
	if qc.server.config.QUICMaxStreamData > 0 {
		streamData = uint64(qc.server.config.QUICMaxStreamData)
	}

	appendTP(quicTPOrigDstCID, qc.getOrigDstCID())
	appendTP(quicTPInitialSrcCID, qc.srcCID())
	if qc.retrySrcLen > 0 {
		appendTP(quicTPRetrySrcCID, qc.retrySrcConnID[:qc.retrySrcLen])
	}
	if qc.server.quicResets != nil {
		tok := qc.server.quicResets.token(qc.srcCID())
		appendTP(quicTPStatelessResetToken, tok[:])
	}
	appendTPVarint(quicTPMaxIdleTimeout, idleMs)
	appendTPVarint(quicTPInitialMaxData, qc.maxDataLocal)
	appendTPVarint(quicTPInitialMaxStreamBidiL, streamData)
	appendTPVarint(quicTPInitialMaxStreamBidiR, streamData)
	appendTPVarint(quicTPInitialMaxStreamUni, streamData)
	appendTPVarint(quicTPInitialMaxStreamsBidi, quicMaxBidiStreams)
	appendTPVarint(quicTPInitialMaxStreamsUni, quicMaxUniStreams)
	appendTPVarint(quicTPActiveConnIDLimit, quicLocalActiveCIDLimit)
	return tp
}

func quicBuildEncryptedExtensions(alpn string, transportParams []byte) []byte {
	var exts []byte

	if alpn != "" {
		alpnExt := BuildALPNExtension(alpn)
		exts = append(exts, alpnExt...)
	}

	tpExtType := uint16(0x0039)
	exts = append(exts, byte(tpExtType>>8), byte(tpExtType))
	exts = append(exts, byte(len(transportParams)>>8), byte(len(transportParams)))
	exts = append(exts, transportParams...)

	body := make([]byte, 2+len(exts))
	body[0] = byte(len(exts) >> 8)
	body[1] = byte(len(exts))
	copy(body[2:], exts)
	return HSWrap(0x08, body)
}

func (ts *quicTLSState) handleClientFinished(qc *QUICConn, data []byte) {
	if len(data) < 4 {
		return
	}
	if data[0] != 0x14 {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] expected Finished (0x14), got 0x%02x", data[0])
		}
		qc.closeWithTLSAlert(alertUnexpectedMessage)
		return
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return
	}

	clientFinData := data[4 : 4+msgLen]

	finHash := make([]byte, 0, ts.hashLen)
	finHash = ts.transcript.Sum(finHash)
	expectedFin := ts.suite.ComputeFinishedTo(ts.clientHSSecret, finHash, nil)
	if len(clientFinData) != len(expectedFin) {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] client Finished length mismatch")
		}
		qc.closeWithTLSAlert(alertDecodeError)
		return
	}
	if subtle.ConstantTimeCompare(clientFinData, expectedFin) != 1 {
		if debugFlag.Load() {
			Dbg("[QUIC-TLS] client Finished verify failed")
		}
		qc.closeWithTLSAlert(alertDecryptError)
		return
	}

	ts.transcript.Write(data[:4+msgLen])
	ts.completeHandshake(qc)
}

func (ts *quicTLSState) completeHandshake(qc *QUICConn) {
	ts.stage = quicTLSStageDone
	qc.handshakeDone.Store(true)
	qc.addressValidated.Store(true)
	qc.clearHandshaking()
	qc.discardKeys(quicSpaceHandshake)

	var frames []byte
	frames = quicAppendHandshakeDoneFrame(frames)
	frames = quicAppendMaxDataFrame(frames, qc.grantedRecvData())
	frames = quicAppendMaxStreamsFrame(frames, quicMaxBidiStreams, true)
	frames = quicAppendMaxStreamsFrame(frames, quicMaxUniStreams, false)
	qc.sendFrames(quicSpaceAppData, frames, true)
	qc.issueConnectionIDs()
	qc.sendNewToken()
	ts.sendSessionTicket(qc)

	if debugFlag.Load() {
		Dbg("[QUIC] handshake complete for %s", qc.remoteAddr.String())
	}

	Stats.H3Conns.Add(1)
	h3 := newH3Conn(qc)
	h3.start()
}
