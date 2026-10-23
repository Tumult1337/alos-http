//go:build linux && amd64

package core

import (
	"net/http"
	"time"
)

const cacheDeltaSecondsMax = 1 << 31

const cacheRFC850GMT = "Monday, 02-Jan-06 15:04:05 GMT"

type cacheFreshness struct {
	lifetime time.Duration
	age      time.Duration
	explicit bool
	noStale  bool
}

type cacheDirective struct {
	lifetime time.Duration
	present  bool
}

func (d *cacheDirective) set(arg string) {
	if d.present {
		return
	}
	d.present = true
	d.lifetime = parseDeltaSeconds(arg)
}

func parseDeltaSeconds(v string) time.Duration {
	var n int64
	for i := range len(v) {
		c := v[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = min(n*10+int64(c-'0'), cacheDeltaSecondsMax)
	}
	return time.Duration(n) * time.Second
}

func parseCacheHTTPDate(v string) (time.Time, bool) {
	for _, layout := range []string{http.TimeFormat, cacheRFC850GMT, time.ANSIC} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func parseCacheAge(v string) time.Duration {
	if end := indexByte(v, ','); end >= 0 {
		v = v[:end]
	}
	return parseDeltaSeconds(trimASCIISpace(v))
}

type cacheFreshnessFields struct {
	maxAge, sMaxAge     cacheDirective
	expires, date       string
	hasExpires, hasDate bool
	age                 time.Duration
	hasAge              bool
	revalidate          bool
}

func (f *cacheFreshnessFields) addCacheControl(value string) {
	for len(value) > 0 {
		token := value
		value = ""
		if end := indexByte(token, ','); end >= 0 {
			token, value = token[:end], token[end+1:]
		}
		name, arg := splitHeaderDirective(trimASCIISpace(token))
		switch {
		case EqualFoldASCII(name, "max-age"):
			f.maxAge.set(arg)
		case EqualFoldASCII(name, "s-maxage"):
			f.sMaxAge.set(arg)
		case EqualFoldASCII(name, "must-revalidate"), EqualFoldASCII(name, "proxy-revalidate"):
			f.revalidate = true
		}
	}
}

func (f *cacheFreshnessFields) add(name, value string) {
	switch {
	case EqualFoldASCII(name, "cache-control"):
		f.addCacheControl(value)
	case EqualFoldASCII(name, "expires") && !f.hasExpires:
		f.expires, f.hasExpires = value, true
	case EqualFoldASCII(name, "date") && !f.hasDate:
		f.date, f.hasDate = value, true
	case EqualFoldASCII(name, "age") && !f.hasAge:
		f.age, f.hasAge = parseCacheAge(value), true
	}
}

func (f *cacheFreshnessFields) parsedDate() (time.Time, bool) {
	if !f.hasDate {
		return time.Time{}, false
	}
	return parseCacheHTTPDate(trimASCIISpace(f.date))
}

func (f *cacheFreshnessFields) expiresLifetime(base time.Time) time.Duration {
	expires, _ := parseCacheHTTPDate(trimASCIISpace(f.expires))
	return expires.Sub(base)
}

func parseCacheFreshness(headers [][2]string, received time.Time) cacheFreshness {
	var f cacheFreshnessFields
	for i := range headers {
		f.add(headers[i][0], headers[i][1])
	}
	base := received
	age := f.age
	if date, ok := f.parsedDate(); ok {
		base = date
		age = max(age, received.Sub(date))
	}
	out := cacheFreshness{age: clampCacheAge(age), noStale: f.revalidate || f.sMaxAge.present}
	switch {
	case f.sMaxAge.present:
		out.explicit, out.lifetime = true, f.sMaxAge.lifetime
	case f.maxAge.present:
		out.explicit, out.lifetime = true, f.maxAge.lifetime
	case f.hasExpires:
		out.explicit, out.lifetime = true, f.expiresLifetime(base)
	}
	return out
}

func clampCacheAge(age time.Duration) time.Duration {
	return min(max(age, 0), cacheDeltaSecondsMax*time.Second)
}

func (f cacheFreshness) storeTTL(configured time.Duration) (time.Duration, bool) {
	if !f.explicit {
		return configured, true
	}
	if f.lifetime <= f.age {
		return 0, false
	}
	return min(configured, f.lifetime-f.age), true
}
