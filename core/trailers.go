//go:build linux && amd64

package core

func trailerFieldForbidden(name string) bool {
	switch len(name) {
	case 4:
		return EqualFoldASCII(name, "host")
	case 7:
		return EqualFoldASCII(name, "trailer")
	case 10:
		return EqualFoldASCII(name, "connection")
	case 14:
		return EqualFoldASCII(name, "content-length")
	case 17:
		return EqualFoldASCII(name, "transfer-encoding")
	}
	return false
}

func appendTrailerField(dst [][2]string, name, value string) [][2]string {
	if trailerFieldForbidden(name) {
		return dst
	}
	return append(dst, [2]string{name, value})
}

func splitTrailerLine(line []byte) (name, value []byte, ok bool) {
	special, nameEnd := h1HeaderLineSpecials(line)
	end, bad := classifyFirstSpecial(line, special)
	if bad || end != len(line)-2 || !validH1Colon(line[:end], nameEnd) {
		return nil, nil, false
	}
	return line[:nameEnd], trimOWS(line[nameEnd+1 : end]), true
}

func h2TrailerFields(fields [][2]string) ([][2]string, bool) {
	var trailers [][2]string
	for _, f := range fields {
		if !isValidH2FieldName(f[0]) || f[0][0] == ':' || !isValidH2FieldValue(f[1]) || isH2ConnectionSpecificField(f[0], f[1]) {
			return nil, false
		}
		trailers = appendTrailerField(trailers, f[0], f[1])
	}
	return trailers, true
}

func (r *Request) Trailers() [][2]string {
	if r.bodyStream != nil {
		return r.bodyStream.Trailers()
	}
	return r.trailers
}
