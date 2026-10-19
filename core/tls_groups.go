//go:build linux && amd64

package core

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
)

type tlsGroup uint16

const (
	groupP256           tlsGroup = 0x0017
	groupX25519         tlsGroup = 0x001d
	groupX25519MLKEM768 tlsGroup = 0x11ec
)

const (
	x25519ShareLen            = 32
	p256ShareLen              = 65
	mlkemHybridClientShareLen = mlkem.EncapsulationKeySize768 + x25519ShareLen
	mlkemHybridServerShareLen = mlkem.CiphertextSize768 + x25519ShareLen
	maxSharedSecretLen        = mlkem.SharedKeySize + x25519ShareLen
)

var (
	groupPreferenceClassical = [...]tlsGroup{groupX25519, groupX25519MLKEM768, groupP256}
	groupPreferencePQ        = [...]tlsGroup{groupX25519MLKEM768, groupX25519, groupP256}
)

func groupPreference(preferPQ bool) []tlsGroup {
	if preferPQ {
		return groupPreferencePQ[:]
	}
	return groupPreferenceClassical[:]
}

func (ch *ParsedClientHello) keyShareFor(g tlsGroup) []byte {
	switch g {
	case groupX25519:
		return ch.x25519Share
	case groupP256:
		return ch.p256Share
	case groupX25519MLKEM768:
		return ch.mlkemShare
	}
	return nil
}

func (ch *ParsedClientHello) supportsGroup(g tlsGroup) bool {
	for _, offered := range ch.SupportedGroups {
		if tlsGroup(offered) == g {
			return true
		}
	}
	return false
}

func (ch *ParsedClientHello) recordKeyShare(g tlsGroup, share []byte) {
	ch.keyShareCount++
	switch g {
	case groupX25519:
		if ch.x25519Share != nil {
			return
		}
		ch.x25519Share = share
		if len(share) == x25519ShareLen {
			copy(ch.x25519PubKeyBuf[:], share)
			ch.X25519PubKey = ch.x25519PubKeyBuf[:]
		}
	case groupP256:
		if ch.p256Share == nil {
			ch.p256Share = share
		}
	case groupX25519MLKEM768:
		if ch.mlkemShare == nil {
			ch.mlkemShare = share
		}
	}
}

type keyShareChoice struct {
	group tlsGroup
	share []byte
	retry bool
}

func selectKeyShare(ch *ParsedClientHello, preferPQ bool) (keyShareChoice, bool) {
	prefs := groupPreference(preferPQ)
	for _, g := range prefs {
		if share := ch.keyShareFor(g); share != nil {
			return keyShareChoice{group: g, share: share}, true
		}
	}
	for _, g := range prefs {
		if ch.supportsGroup(g) {
			return keyShareChoice{group: g, retry: true}, true
		}
	}
	return keyShareChoice{}, false
}

type serverKeyShare struct {
	shareLen  int
	secretLen int
	shareBuf  [mlkemHybridServerShareLen]byte
	secretBuf [maxSharedSecretLen]byte
}

func (kx *serverKeyShare) share() []byte { return kx.shareBuf[:kx.shareLen] }

func (kx *serverKeyShare) secret() []byte { return kx.secretBuf[:kx.secretLen] }

func (kx *serverKeyShare) appendShare(b []byte) {
	kx.shareLen += copy(kx.shareBuf[kx.shareLen:], b)
}

func (kx *serverKeyShare) appendSecret(b []byte) {
	kx.secretLen += copy(kx.secretBuf[kx.secretLen:], b)
}

func (kx *serverKeyShare) extractHandshakeSecret(cs *CipherSuiteConfig, salt, dst []byte) []byte {
	var ikm [maxSharedSecretLen]byte
	n := copy(ikm[:], kx.secret())
	out := TLSExtractTo(cs.HashFn, salt, ikm[:n], dst)
	clear(ikm[:])
	return out
}

func (kx *serverKeyShare) wipe() {
	clear(kx.secretBuf[:])
}

func (s *Server) completeKeyShare(kx *serverKeyShare, group tlsGroup, clientShare []byte) (tlsAlert, bool) {
	switch group {
	case groupX25519:
		if len(clientShare) != x25519ShareLen {
			return alertIllegalParameter, false
		}
		return s.appendX25519Share(kx, clientShare)
	case groupX25519MLKEM768:
		return s.completeMLKEMHybridShare(kx, clientShare)
	case groupP256:
		return completeP256Share(kx, clientShare)
	}
	return alertInternalError, false
}

func (s *Server) appendX25519Share(kx *serverKeyShare, peer []byte) (tlsAlert, bool) {
	kp, err := s.x25519Pool.Get()
	if err != nil {
		return alertInternalError, false
	}
	defer kp.zero()
	shared, ok := kp.sharedSecret(peer)
	if !ok {
		return alertIllegalParameter, false
	}
	kx.appendShare(kp.pub[:])
	kx.appendSecret(shared[:])
	clear(shared[:])
	return 0, true
}

func (s *Server) completeMLKEMHybridShare(kx *serverKeyShare, clientShare []byte) (tlsAlert, bool) {
	if len(clientShare) != mlkemHybridClientShareLen {
		return alertIllegalParameter, false
	}
	ek, err := mlkem.NewEncapsulationKey768(clientShare[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return alertIllegalParameter, false
	}
	mlkemSecret, ciphertext := ek.Encapsulate()
	kx.appendShare(ciphertext)
	kx.appendSecret(mlkemSecret)
	clear(mlkemSecret)
	return s.appendX25519Share(kx, clientShare[mlkem.EncapsulationKeySize768:])
}

func completeP256Share(kx *serverKeyShare, clientShare []byte) (tlsAlert, bool) {
	if len(clientShare) != p256ShareLen {
		return alertIllegalParameter, false
	}
	peer, err := ecdh.P256().NewPublicKey(clientShare)
	if err != nil {
		return alertIllegalParameter, false
	}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return alertInternalError, false
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return alertIllegalParameter, false
	}
	kx.appendShare(priv.PublicKey().Bytes())
	kx.appendSecret(shared)
	clear(shared)
	return 0, true
}
