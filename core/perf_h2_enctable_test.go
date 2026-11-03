//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

type perfH2EncCase struct {
	status      int
	contentType string
	length      int64
	headers     [][2]string
}

var perfH2EncCases = []perfH2EncCase{
	{200, "text/plain", 13, nil},
	{200, "text/plain", 13, [][2]string{{"Alt-Svc", `h3=":443"; ma=86400`}}},
	{404, "application/json", 27, [][2]string{{"Access-Control-Allow-Origin", "*"}, {"X-RateLimit-Remaining", "99"}}},
	{200, "text/plain", 2, [][2]string{{"Set-Cookie", "sid=secret"}, {"Vary", "Accept-Encoding"}}},
	{200, "text/plain", 13, [][2]string{{"Cache-Control", strings.Repeat("x", h2EncIndexMaxValue+1)}}},
}

func perfH2EncodeIndexed(tbl *hpackEncTable, c perfH2EncCase) []byte {
	enc := HpackEncoder{}
	encodeH2ResponseHeadersIndexed(&enc, tbl, c.status, c.contentType, c.length, c.headers, "ALOS")
	return enc.Buf
}

func perfH2EncodeStateless(c perfH2EncCase) []byte {
	enc := HpackEncoder{}
	encodeH2ResponseHeaders(&enc, c.status, c.contentType, c.length, c.headers, "ALOS")
	return enc.Buf
}

func perfH2SameFields(t *testing.T, round int, got, want [][2]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("round %d: %d fields %q, want %d %q", round, len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("round %d field %d: %q, want %q", round, i, got[i], want[i])
		}
	}
}

func TestH2IndexedResponseHeadersDecodeLikeStateless(t *testing.T) {
	var tbl hpackEncTable
	tbl.reset()
	client := &HpackDecoder{maxTableSize: 4096, protocolMaxSize: 4096, maxHeaderListSize: 1 << 20}
	reference := &HpackDecoder{maxTableSize: 4096, protocolMaxSize: 4096, maxHeaderListSize: 1 << 20}
	for round := 0; round < 4; round++ {
		for i, c := range perfH2EncCases {
			block := perfH2EncodeIndexed(&tbl, c)
			got, err := client.DecodeInto(nil, block)
			if err != nil {
				t.Fatalf("round %d case %d: decode indexed block: %v", round, i, err)
			}
			want, err := reference.DecodeInto(nil, perfH2EncodeStateless(c))
			if err != nil {
				t.Fatalf("round %d case %d: decode stateless block: %v", round, i, err)
			}
			perfH2SameFields(t, round, got, want)
			if round > 0 && len(block) >= len(perfH2EncodeStateless(c)) && c.headers == nil {
				t.Fatalf("round %d case %d: indexed block %d B is not smaller than stateless %d B", round, i, len(block), len(perfH2EncodeStateless(c)))
			}
		}
	}
	for _, e := range tbl.entries {
		if e.name == "set-cookie" || e.name == "x-ratelimit-remaining" || e.name == "content-length" {
			t.Fatalf("volatile or sensitive field %q entered the encoder table", e.name)
		}
		if len(e.value) > h2EncIndexMaxValue {
			t.Fatalf("oversized value of %q entered the encoder table", e.name)
		}
	}
}

func TestH2IndexedResponseHeadersFollowPeerTableSize(t *testing.T) {
	for _, limit := range []uint32{0, 100, 1 << 20} {
		var tbl hpackEncTable
		tbl.reset()
		client := &HpackDecoder{maxTableSize: 4096, protocolMaxSize: 4096, maxHeaderListSize: 1 << 20}
		for _, c := range perfH2EncCases {
			if _, err := client.DecodeInto(nil, perfH2EncodeIndexed(&tbl, c)); err != nil {
				t.Fatalf("limit %d warm-up: %v", limit, err)
			}
		}
		tbl.setPeerLimit(limit)
		effective := int(min(limit, h2EncTableMaxSize))
		client.protocolMaxSize = effective
		for round := 0; round < 3; round++ {
			for i, c := range perfH2EncCases {
				if _, err := client.DecodeInto(nil, perfH2EncodeIndexed(&tbl, c)); err != nil {
					t.Fatalf("limit %d round %d case %d: %v", limit, round, i, err)
				}
				if tbl.size > effective {
					t.Fatalf("limit %d: encoder table holds %d bytes", limit, tbl.size)
				}
			}
		}
	}
}
