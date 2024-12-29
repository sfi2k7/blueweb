package blueweb

import "sync"

type store struct {
	m  map[string]interface{}
	mu sync.Mutex
}

func newStore() *store {
	return &store{
		m: make(map[string]interface{}),
	}
}

func (s *store) Set(k string, v interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.m[k] = v
}

func (s *store) Get(k string) interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.m[k]
}

func (s *store) Del(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.m, k)
}

func (s *store) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	return keys
}

func (s *store) Values() []interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	values := make([]interface{}, 0, len(s.m))
	for _, v := range s.m {
		values = append(values, v)
	}
	return values
}

func (s *store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.m)
}

func (s *store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.m = make(map[string]interface{})
}

func (s *store) ForEach(f func(k string, v interface{})) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range s.m {
		f(k, v)
	}
}

func (s *store) DeleteFiltered(f func(k string, v interface{}) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range s.m {
		if f(k, v) {
			delete(s.m, k)
		}
	}
}

func (s *store) Filter(f func(k string, v interface{}) bool) map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]interface{})
	for k, v := range s.m {
		if f(k, v) {
			result[k] = v
		}
	}
	return result
}
