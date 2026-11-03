//go:build linux && amd64

package core

func dateEligible(status int, headers [][2]string) bool {
	return status >= 200 && status < 600 && !headersHaveFold(headers, "date")
}

func responseDateValue(status int, headers [][2]string) string {
	if !dateEligible(status, headers) {
		return ""
	}
	return currentHTTPDate().text
}

func appendH1Date(dst []byte, date string) []byte {
	dst = append(dst, "Date: "...)
	dst = append(dst, date...)
	return append(dst, '\r', '\n')
}

func appendProxyDate(dst []byte, status int, headers respHeaders) []byte {
	if status < 200 || status >= 600 {
		return dst
	}
	for index := 0; index < headers.count(); index++ {
		if headers.nameIs(index, "date") {
			return dst
		}
	}
	return appendH1Date(dst, currentHTTPDate().text)
}

func (p *h1Parser) wantsReceiptDate() bool {
	return p.status == 101 || (p.status >= 200 && p.status < 600)
}

func (p *h1Parser) addReceiptDate() {
	for _, header := range p.hdr {
		if headerNameIsBytes(header[0], "date") {
			return
		}
	}
	p.receiptDateBuf = append(p.receiptDateBuf[:0], "date"...)
	nameEnd := len(p.receiptDateBuf)
	p.receiptDateBuf = append(p.receiptDateBuf, currentHTTPDate().text...)
	p.hdr = append(p.hdr, [2][]byte{p.receiptDateBuf[:nameEnd], p.receiptDateBuf[nameEnd:]})
}

func responseHeaderValue(name, value []byte) string {
	if string(name) == "date" {
		if text := currentHTTPDate().text; string(value) == text {
			return text
		}
	}
	return string(value)
}
