package airouterv3

type node struct {
	path      string
	children  []*node
	isParam   bool
	paramName string

	handler    map[string]Handler // single handlers map per node
	param      string
	isCatchAll bool
	isStatic   bool
	paramDef   *ParamDefinition
}

// findChild - optimized child finding
func (n *node) findChild(path string) *node {
	for i := 0; i < len(n.children); i++ {
		if n.children[i].path == path {
			return n.children[i]
		}
	}
	return nil
}
