//go:build linux && amd64

package core

const (
	h2HeadMemoMaxFields   = 16
	h2HeadMemoMaxKey      = 1024
	h2HeadMemoMissBackoff = 64
)

type h2HeadMemo struct {
	gen           uint32
	status        int
	contentLength int64
	date          *h2DateField
	ctLen         int
	key           []byte
	headerLens    []int
	block         []byte
	probation     bool
	skip          int
}

func (t *hpackEncTable) headMemoReady(headers [][2]string) bool {
	if m := t.headMemo; m != nil && m.skip > 0 {
		m.skip--
		return false
	}
	return len(headers) == 0 || h2HeadMemoEligible(headers)
}

func h2HeadMemoEligible(headers [][2]string) bool {
	if len(headers) > h2HeadMemoMaxFields {
		return false
	}
	n := 0
	for i := range headers {
		n += len(headers[i][0]) + len(headers[i][1])
	}
	return n <= h2HeadMemoMaxKey && !headersHaveFold(headers, "date")
}

func (m *h2HeadMemo) matches(gen uint32, date *h2DateField, status int, contentType string, contentLength int64, headers [][2]string, serverName string) bool {
	if m.gen != gen || m.date != date || m.status != status || m.contentLength != contentLength ||
		len(m.headerLens) != 2*len(headers) || len(m.block) == 0 || m.ctLen != len(contentType) {
		return false
	}
	n := m.ctLen + len(serverName)
	if len(m.key) < n || string(m.key[:m.ctLen]) != contentType || string(m.key[m.ctLen:n]) != serverName {
		return false
	}
	if len(headers) == 0 {
		return len(m.key) == n
	}
	return m.headersMatch(n, headers)
}

func (m *h2HeadMemo) headersMatch(off int, headers [][2]string) bool {
	for i := range headers {
		for j, s := range headers[i] {
			n := m.headerLens[2*i+j]
			if n != len(s) || off+n > len(m.key) || string(m.key[off:off+n]) != s {
				return false
			}
			off += n
		}
	}
	return off == len(m.key)
}

func (m *h2HeadMemo) remember(gen uint32, date *h2DateField, status int, contentType string, contentLength int64, headers [][2]string, serverName string, block []byte) {
	m.gen = gen
	m.date = date
	m.status = status
	m.contentLength = contentLength
	m.ctLen = len(contentType)
	m.key = append(append(m.key[:0], contentType...), serverName...)
	m.headerLens = m.headerLens[:0]
	for i := range headers {
		m.headerLens = append(m.headerLens, len(headers[i][0]), len(headers[i][1]))
		m.key = append(append(m.key, headers[i][0]...), headers[i][1]...)
	}
	m.block = append(m.block[:0], block...)
	m.probation = true
}

func encodeH2ResponseHeadersRemembered(enc *HpackEncoder, tbl *hpackEncTable, date *h2DateField, statusCode int, contentType string, contentLength int64, headers [][2]string, serverName string) {
	gen, start := tbl.gen, len(enc.Buf)
	encodeH2ResponseHeadersDated(enc, tbl, date, statusCode, contentType, contentLength, headers, serverName)
	if tbl.gen != gen {
		return
	}
	m := tbl.headMemo
	if m == nil {
		m = &h2HeadMemo{}
		tbl.headMemo = m
	} else if m.probation && m.gen == gen && m.date == date {
		m.probation = false
		m.skip = h2HeadMemoMissBackoff
		return
	}
	m.remember(gen, date, statusCode, contentType, contentLength, headers, serverName, enc.Buf[start:])
}
