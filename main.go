package blueweb

import "sync"

type O map[string]interface{}

type reqcount struct {
	r map[string]uint64
	s sync.Mutex
}

func (r *reqcount) Add(k string) {
	r.s.Lock()
	defer r.s.Unlock()

	if r.r == nil {
		r.r = make(map[string]uint64)
	}
	r.r[k]++
}

func (r *reqcount) Get(k string) uint64 {
	r.s.Lock()
	defer r.s.Unlock()

	if r.r == nil {
		return 0
	}
	return r.r[k]
}
