//go:build linux && amd64

package core

const (
	tlsHSKeyUpdate          = 24
	keyUpdateNotRequested   = 0
	keyUpdateRequested      = 1
	keyUpdateBodyLen        = 1
	keyUpdateMessageLen     = tlsHandshakeHeaderLen + keyUpdateBodyLen
	tls13RecordsPerKeyLimit = 1 << 24
	tlsMaxUselessRecords    = 16
)

var errTLSRekeyFailed = &staticError{"tls: traffic key update failed"}

func parseKeyUpdate(msg []byte) (requested bool, alert tlsAlert, ok bool) {
	if len(msg) < tlsHandshakeHeaderLen || msg[0] != tlsHSKeyUpdate {
		return false, alertUnexpectedMessage, false
	}
	if int(msg[1])<<16|int(msg[2])<<8|int(msg[3]) != keyUpdateBodyLen || len(msg) < keyUpdateMessageLen {
		return false, alertDecodeError, false
	}
	if len(msg) != keyUpdateMessageLen {
		return false, alertUnexpectedMessage, false
	}
	switch msg[tlsHandshakeHeaderLen] {
	case keyUpdateNotRequested:
		return false, 0, true
	case keyUpdateRequested:
		return true, 0, true
	}
	return false, alertIllegalParameter, false
}

func (t *TrafficAEAD) advanceGeneration() bool {
	var next TrafficAEAD
	if t.nextGeneration(&next) != nil {
		return false
	}
	*t = next
	return true
}

func appendKeyUpdateRecord(dst []byte, w *TrafficAEAD) ([]byte, bool) {
	var next TrafficAEAD
	if w.nextGeneration(&next) != nil {
		return dst, false
	}
	msg := [keyUpdateMessageLen + 1]byte{tlsHSKeyUpdate, 0, 0, keyUpdateBodyLen, keyUpdateNotRequested, tlsRecHandshake}
	dst = appendTLSInnerRecord(dst, w, msg[:])
	*w = next
	return dst, true
}
