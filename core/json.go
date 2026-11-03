//go:build linux && amd64

package core

import (
	"sync"

	"github.com/bytedance/sonic"
	"github.com/bytedance/sonic/encoder"
)

// JSON is a pooled JSON encoder backed by sonic. Acquire one with AcquireJSON,
// call Marshal to encode a value, then Release to return it to the pool.
//
//	j := core.AcquireJSON()
//	defer j.Release()
//	resp.Status(200).JSON(j.Marshal(myStruct))
type JSON struct {
	Buf []byte
}

var jsonPool = sync.Pool{
	New: func() any {
		return &JSON{}
	},
}

// AcquireJSON returns a pooled JSON encoder. Call Release when done to return
// it to the pool and avoid allocations.
//
//	j := core.AcquireJSON()
//	defer j.Release()
//	data := j.Marshal(payload)
func AcquireJSON() *JSON {
	return jsonPool.Get().(*JSON)
}

// Marshal encodes v to JSON and returns the bytes; on failure it logs the error and returns the literal null.
//
// Example: data := j.Marshal(User{Name: "ada"})
// Example: resp.Status(200).JSON(j.Marshal(map[string]int{"count": 3}))
func (j *JSON) Marshal(v any) []byte {
	data, err := sonic.Marshal(v)
	if err != nil {
		logger().Error("JSON marshal failed", "err", err)
		return []byte("null")
	}
	return data
}

const sonicDefaultEncodeOptions encoder.Options = 0

func (j *JSON) MarshalInto(v any) ([]byte, error) {
	j.Buf = j.Buf[:0]
	if err := encoder.EncodeInto(&j.Buf, v, sonicDefaultEncodeOptions); err != nil {
		j.Buf = j.Buf[:0]
		return nil, err
	}
	return j.Buf, nil
}

// Release returns the encoder to the pool for reuse; do not use it after calling Release.
//
// Example: defer j.Release()
func (j *JSON) Release() {
	if cap(j.Buf) > bufferShrinkThreshold {
		j.Buf = nil
	}
	j.Buf = j.Buf[:0]
	jsonPool.Put(j)
}
