//go:build linux && amd64

package core

type tlsAlert uint8

const (
	alertCloseNotify           tlsAlert = 0
	alertUnexpectedMessage     tlsAlert = 10
	alertBadRecordMAC          tlsAlert = 20
	alertRecordOverflow        tlsAlert = 22
	alertHandshakeFailure      tlsAlert = 40
	alertIllegalParameter      tlsAlert = 47
	alertDecodeError           tlsAlert = 50
	alertDecryptError          tlsAlert = 51
	alertProtocolVersion       tlsAlert = 70
	alertInappropriateFallback tlsAlert = 86
	alertInternalError         tlsAlert = 80
	alertUnrecognizedName      tlsAlert = 112
	alertNoApplicationProtocol tlsAlert = 120
)

const (
	tlsAlertLevelWarning  = 1
	tlsAlertLevelFatal    = 2
	tlsMinLegacyVersion   = 0x0303
	tlsHandshakeHeaderLen = 4
)

const (
	tlsSCSVRenegotiation       = 0x00ff
	tlsSCSVFallback            = 0x5600
	tlsExtExtendedMasterSecret = 0x0017
	tlsExtRenegotiationInfo    = 0xff01
	tls12RandomLen             = 32
)

const tls13DowngradeSentinel = "DOWNGRD\x01"

func certMissAlert(serverName string) tlsAlert {
	if serverName != "" {
		return alertUnrecognizedName
	}
	return alertHandshakeFailure
}

func signFailureAlert(err error) tlsAlert {
	if err == errNoCommonSignatureScheme {
		return alertHandshakeFailure
	}
	return alertInternalError
}

func (ch *ParsedClientHello) rejectsProtocolVersion() bool {
	return !ch.SupportsTLS13() && ch.LegacyVersion < tlsMinLegacyVersion
}

func (ch *ParsedClientHello) inappropriateFallback() bool {
	return ch.fallbackSCSV && !ch.SupportsTLS13()
}

func (ch *ParsedClientHello) offersALPN(proto string) bool {
	for _, p := range ch.ALPNProtos {
		if p == proto {
			return true
		}
	}
	return false
}
