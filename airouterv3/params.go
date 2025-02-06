package airouterv3

// Params holds URL parameters
type Params struct {
	params    map[string]string
	maxParams int
}

// NewParams creates a new parameter store
func NewParams(maxParams int) *Params {
	return &Params{
		params:    make(map[string]string, maxParams),
		maxParams: maxParams,
	}
}

// Add adds a parameter
func (p *Params) Add(name, value string) {
	if len(p.params) < p.maxParams {
		p.params[name] = value
	}
}

// Get retrieves a parameter value
func (p *Params) Get(name string) string {
	return p.params[name]
}

// GetAll returns all parameters
func (p *Params) GetAll() map[string]string {
	return p.params
}

// Reset clears all parameters
func (p *Params) Reset() {
	for k := range p.params {
		delete(p.params, k)
	}
}

// Count returns number of parameters
func (p *Params) Count() int {
	return len(p.params)
}
