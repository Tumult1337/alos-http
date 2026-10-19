//go:build linux && amd64

package core

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

const fpFix2LargeRRsetSize = 60

func fpFix2TruncatedReply(query []byte, records ...[]byte) []byte {
	msg := fpFixDNSReply(query, 0, records...)
	msg[2] |= dnsFlagTruncated
	return msg
}

func fpFix2AdvertisedPayload(query []byte) int {
	_, end := fpReadDNSName(query, dnsHeaderLen)
	opt := end + dnsQuestionFixedLen
	if end < 0 || query[10] != 0 || query[11] != 1 || len(query) < opt+5 || query[opt] != 0 || query[opt+1] != 0 || query[opt+2] != 41 {
		return 0
	}
	return int(query[opt+3])<<8 | int(query[opt+4])
}

func TestFPFix2DNSQueryAdvertisesEDNS0Payload(t *testing.T) {
	q := appendDNSQuery(nil, 7, "origin.test", dnsTypeA)
	question := []byte{6, 'o', 'r', 'i', 'g', 'i', 'n', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	wantOPT := []byte{0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0}
	want := append([]byte{0, 7, dnsFlagsRecursionDesired, 0, 0, 1, 0, 0, 0, 0, 0, 1}, question...)
	want = append(want, wantOPT...)
	if !bytes.Equal(q, want) {
		t.Fatalf("query\n got % x\nwant % x", q, want)
	}
	if got := fpFix2AdvertisedPayload(q); got != 1232 {
		t.Fatalf("advertised payload %d, want 1232", got)
	}
}

func TestFPFix2DNSTruncatedReplyKeepsOnlyCompleteRecords(t *testing.T) {
	a := fpFixARecord([4]byte{10, 0, 0, 7})
	cname := dnsRecord(dnsTypeCNAME, 60, []byte{3, 'f', 'o', 'o', 0})
	target := append([]byte{3, 'f', 'o', 'o', 0}, 0, 1, 0, 1, 0, 0, 0, 90, 0, 4, 10, 0, 0, 9)
	truncate := func(msg []byte) []byte {
		msg[2] |= dnsFlagTruncated
		return msg
	}
	cutRecord := truncate(dnsAnswer(7, a, a))
	cutRecord = cutRecord[:len(cutRecord)-2]
	for _, tc := range []struct {
		name string
		msg  []byte
		want string
		err  error
	}{
		{"complete record in a truncated reply", truncate(dnsAnswer(7, a)), "10.0.0.7", nil},
		{"complete cname chain in a truncated reply", truncate(dnsAnswer(7, cname, target)), "10.0.0.9", nil},
		{"first record complete, second cut", cutRecord, "10.0.0.7", nil},
		{"only record cut mid-data", truncate(dnsAnswer(7, a))[:len(dnsAnswer(7, a))-2], "", errFPDNSFailed},
		{"truncated with the rrset omitted", truncate(dnsAnswer(7)), "", errFPDNSFailed},
		{"truncated with only a foreign record", truncate(dnsAnswerFor(7, dnsTypeA, dnsRecord(dnsTypeAAAA, 60, make([]byte, 16)))), "", errFPDNSFailed},
	} {
		addr, _, err := fpParseDNSResponse(tc.msg, 7, dnsTypeA, "origin.test")
		if err != tc.err || (tc.err == nil && addr != netip.MustParseAddr(tc.want)) {
			t.Errorf("%s: %v %v, want %s %v", tc.name, addr, err, tc.want, tc.err)
		}
	}
}

func TestFPFix2DNSTruncatedReplyStillReachesBackend(t *testing.T) {
	_, port := fpFixLoopbackOrigin(t)
	host := fpFixHostName(t)
	fpFixStartDNS(t, func(s *fpFixDNSServer, query []byte, from *net.UDPAddr) {
		s.reply(from, fpFix2TruncatedReply(query, fpFixARecord([4]byte{127, 0, 0, 1})))
	})
	resp, err := fpFixClientGet(t, host+":"+port)
	if err != nil || resp.Status != 200 || string(resp.Body) != "ok" {
		t.Fatalf("truncated reply with a complete record: %v %+v", err, resp)
	}
}

func TestFPFix2DNSLargeRRsetFitsThroughEDNS0(t *testing.T) {
	_, port := fpFixLoopbackOrigin(t)
	host := fpFixHostName(t)
	records := make([][]byte, fpFix2LargeRRsetSize)
	for i := range records {
		records[i] = fpFixARecord([4]byte{127, 0, 0, 1})
	}
	fpFixStartDNS(t, func(s *fpFixDNSServer, query []byte, from *net.UDPAddr) {
		full := fpFixDNSReply(query, 0, records...)
		if len(full) > fpFix2AdvertisedPayload(query) {
			s.reply(from, fpFix2TruncatedReply(query))
			return
		}
		s.reply(from, full)
	})
	resp, err := fpFixClientGet(t, host+":"+port)
	if err != nil || resp.Status != 200 || string(resp.Body) != "ok" {
		t.Fatalf("large rrset: %v %+v", err, resp)
	}
}
