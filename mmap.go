package blueweb

import "sync"

// Hub Code
type cmap struct {
	m     map[string]*wshandler
	_lock sync.Mutex
}

// add adds entry.
// Add a new entry to the map
func (m *cmap) add(id string, h *wshandler) {
	m._lock.Lock()
	defer m._lock.Unlock()

	m.m[id] = h
}

func (m *cmap) remove(id string) error {
	m._lock.Lock()
	defer m._lock.Unlock()

	delete(m.m, id)

	return nil
}

func (m *cmap) count() int {
	return len(m.m)
}

// func (m *cmap) get(id string) *genericconnectionhandler {
// 	h, ok := m.m[id]
// 	if !ok {
// 		return nil
// 	}
// 	return h
// }

func (m *cmap) closeAll() {
	// m._lock.Lock()
	// defer m._lock.Unlock()

	if m.count() == 0 {
		return
	}

	for _, h := range m.m {
		if h == nil || !h.isopen {
			continue
		}
		h.isopen = false
		// h.Terminate()
	}
}

func (m *cmap) send(id string, data WsData) {
	m._lock.Lock()
	defer m._lock.Unlock()

	h, ok := m.m[id]
	if !ok || !h.isopen {
		return
	}

	h.out.In(data)
}

func (m *cmap) broadcast(data WsData, exclude ...string) {
	m._lock.Lock()
	defer m._lock.Unlock()

	for _, h := range m.m {
		if len(exclude) > 0 {
			if h.ID == exclude[0] {
				continue
			}
		}

		if h == nil || !h.isopen {
			continue
		}

		h.out.In(data)
	}
}

// func newcmap() *cmap {
// 	return &cmap{
// 		m:     make(map[string]*wshandler),
// 		_lock: &sync.Mutex{},
// 	}
// }
