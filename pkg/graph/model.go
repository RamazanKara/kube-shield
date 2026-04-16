package graph

import (
	"fmt"
	"strings"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
)

// NodeType represents a type of node in the security graph.
type NodeType string

const (
	NodePod            NodeType = "Pod"
	NodeServiceAccount NodeType = "ServiceAccount"
	NodeRole           NodeType = "Role"
	NodeClusterRole    NodeType = "ClusterRole"
	NodeSecret         NodeType = "Secret"
	NodeNamespace      NodeType = "Namespace"
	NodeExternal       NodeType = "External"
)

// Node represents a node in the security graph.
type Node struct {
	ID        string   `json:"id"`
	Type      NodeType `json:"type"`
	Name      string   `json:"name"`
	Namespace string   `json:"namespace,omitempty"`
	Risk      float64  `json:"risk"`
}

func (n Node) String() string {
	if n.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", n.Namespace, n.Type, n.Name)
	}
	return fmt.Sprintf("%s/%s", n.Type, n.Name)
}

// EdgeType represents the relationship between nodes.
type EdgeType string

const (
	EdgeRBACGrant     EdgeType = "rbac-grant"
	EdgeNetworkAccess EdgeType = "network-access"
	EdgeMountSecret   EdgeType = "mounts-secret"
	EdgeUsesAccount   EdgeType = "uses-sa"
	EdgeBindsRole     EdgeType = "binds-role"
)

// Edge represents a connection between nodes.
type Edge struct {
	From  string   `json:"from"`
	To    string   `json:"to"`
	Type  EdgeType `json:"type"`
	Label string   `json:"label,omitempty"`
	Risk  float64  `json:"risk"`
}

// SecurityGraph models the cluster as a directed graph for attack path analysis.
type SecurityGraph struct {
	Nodes map[string]*Node
	Edges []Edge
}

// NewSecurityGraph creates an empty security graph.
func NewSecurityGraph() *SecurityGraph {
	return &SecurityGraph{
		Nodes: make(map[string]*Node),
	}
}

// AddNode adds a node to the graph.
func (g *SecurityGraph) AddNode(n *Node) {
	g.Nodes[n.ID] = n
}

// AddEdge adds an edge to the graph.
func (g *SecurityGraph) AddEdge(e Edge) {
	g.Edges = append(g.Edges, e)
}

// AttackPath represents a sequence of hops from an entry point to a target.
type AttackPath struct {
	Nodes   []*Node `json:"nodes"`
	Edges   []Edge  `json:"edges"`
	Risk    float64 `json:"risk"`
	Summary string  `json:"summary"`
}

// FindAttackPaths finds paths from internet-facing pods to sensitive resources.
func (g *SecurityGraph) FindAttackPaths(maxDepth int) []AttackPath {
	if maxDepth <= 0 {
		maxDepth = 6
	}

	// Build adjacency list
	adj := make(map[string][]Edge)
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e)
	}

	// Find entry points (pods with external access or high-risk configs)
	var entryPoints []string
	for id, node := range g.Nodes {
		if node.Type == NodePod && node.Risk > 0.5 {
			entryPoints = append(entryPoints, id)
		}
		if node.Type == NodeExternal {
			entryPoints = append(entryPoints, id)
		}
	}

	// Find targets (secrets, cluster-admin roles)
	targets := make(map[string]bool)
	for id, node := range g.Nodes {
		if node.Type == NodeSecret {
			targets[id] = true
		}
		if node.Type == NodeClusterRole && node.Name == "cluster-admin" {
			targets[id] = true
		}
	}

	// BFS from each entry point
	var paths []AttackPath
	for _, start := range entryPoints {
		found := g.bfs(start, targets, adj, maxDepth)
		paths = append(paths, found...)
	}

	return paths
}

func (g *SecurityGraph) bfs(start string, targets map[string]bool, adj map[string][]Edge, maxDepth int) []AttackPath {
	type state struct {
		nodeID string
		path   []*Node
		edges  []Edge
	}

	var paths []AttackPath
	visited := make(map[string]bool)
	queue := []state{{nodeID: start, path: []*Node{g.Nodes[start]}}}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if len(curr.path) > maxDepth {
			continue
		}

		if targets[curr.nodeID] && len(curr.path) > 1 {
			risk := 0.0
			for _, e := range curr.edges {
				risk += e.Risk
			}
			paths = append(paths, AttackPath{
				Nodes:   curr.path,
				Edges:   curr.edges,
				Risk:    risk / float64(len(curr.edges)),
				Summary: buildPathSummary(curr.path, curr.edges),
			})
			continue
		}

		visited[curr.nodeID] = true

		for _, edge := range adj[curr.nodeID] {
			if !visited[edge.To] {
				newPath := make([]*Node, len(curr.path))
				copy(newPath, curr.path)
				newPath = append(newPath, g.Nodes[edge.To])

				newEdges := make([]Edge, len(curr.edges))
				copy(newEdges, curr.edges)
				newEdges = append(newEdges, edge)

				queue = append(queue, state{
					nodeID: edge.To,
					path:   newPath,
					edges:  newEdges,
				})
			}
		}
	}

	return paths
}

func buildPathSummary(nodes []*Node, edges []Edge) string {
	var parts []string
	for i, n := range nodes {
		if i > 0 {
			parts = append(parts, fmt.Sprintf("→[%s]→", edges[i-1].Type))
		}
		parts = append(parts, n.String())
	}
	return strings.Join(parts, " ")
}

// RenderASCII renders the attack paths as ASCII art.
func RenderASCII(paths []AttackPath) string {
	if len(paths) == 0 {
		return "No attack paths found."
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Found %d attack path(s):\n\n", len(paths))

	for i, path := range paths {
		fmt.Fprintf(&sb, "Path %d (Risk: %.1f):\n", i+1, path.Risk)
		for j, node := range path.Nodes {
			if j == 0 {
				fmt.Fprintf(&sb, "  🔴 %s\n", node.String())
			} else if j == len(path.Nodes)-1 {
				fmt.Fprintf(&sb, "  └─ 🎯 %s\n", node.String())
			} else {
				fmt.Fprintf(&sb, "  │  ↓ [%s]\n", path.Edges[j-1].Type)
				fmt.Fprintf(&sb, "  ├─ %s\n", node.String())
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// ExportDOT exports the graph in Graphviz DOT format.
func (g *SecurityGraph) ExportDOT() string {
	var sb strings.Builder
	sb.WriteString("digraph SecurityGraph {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=rounded];\n\n")

	for _, n := range g.Nodes {
		color := nodeColor(n.Type)
		fmt.Fprintf(&sb, "  %q [label=%q, color=%q];\n", n.ID, n.String(), color)
	}

	sb.WriteString("\n")
	for _, e := range g.Edges {
		fmt.Fprintf(&sb, "  %q -> %q [label=%q];\n", e.From, e.To, e.Type)
	}

	sb.WriteString("}\n")
	return sb.String()
}

func nodeColor(t NodeType) string {
	switch t {
	case NodePod:
		return "blue"
	case NodeServiceAccount:
		return "green"
	case NodeRole, NodeClusterRole:
		return "orange"
	case NodeSecret:
		return "red"
	case NodeExternal:
		return "purple"
	default:
		return "gray"
	}
}

// BuildFromFindings creates a SecurityGraph from scan findings,
// mapping resources and their security relationships.
func BuildFromFindings(findings []engine.Finding) *SecurityGraph {
	g := NewSecurityGraph()

	for _, f := range findings {
		if f.Severity < engine.SeverityHigh {
			continue
		}

		resourceID := fmt.Sprintf("%s/%s/%s", f.Resource.Namespace, f.Resource.Kind, f.Resource.Name)

		// Determine node type from resource kind
		nodeType := NodePod
		switch strings.ToLower(f.Resource.Kind) {
		case "serviceaccount":
			nodeType = NodeServiceAccount
		case "role":
			nodeType = NodeRole
		case "clusterrole":
			nodeType = NodeClusterRole
		case "secret":
			nodeType = NodeSecret
		case "namespace":
			nodeType = NodeNamespace
		}

		g.AddNode(&Node{ID: resourceID, Type: nodeType, Name: f.Resource.Name, Namespace: f.Resource.Namespace, Risk: float64(f.Severity)})

		// Create edges based on check patterns
		switch {
		case strings.HasPrefix(f.CheckID, "RBAC-01"): // secret access
			secretTarget := fmt.Sprintf("%s/Secret/*", f.Resource.Namespace)
			g.AddNode(&Node{ID: secretTarget, Type: NodeSecret, Name: "secrets", Namespace: f.Resource.Namespace, Risk: 3})
			g.AddEdge(Edge{From: resourceID, To: secretTarget, Type: EdgeRBACGrant, Label: "secret access", Risk: float64(f.Severity)})

		case strings.HasPrefix(f.CheckID, "RBAC-02"): // priv escalation
			g.AddNode(&Node{ID: "cluster/escalation", Type: NodeExternal, Name: "privilege-escalation", Risk: 4})
			g.AddEdge(Edge{From: resourceID, To: "cluster/escalation", Type: EdgeRBACGrant, Label: "escalation verbs", Risk: float64(f.Severity)})

		case strings.HasPrefix(f.CheckID, "RBAC-03"): // cluster-admin
			g.AddNode(&Node{ID: "cluster/admin", Type: NodeExternal, Name: "full-cluster-control", Risk: 4})
			g.AddEdge(Edge{From: resourceID, To: "cluster/admin", Type: EdgeBindsRole, Label: "cluster-admin", Risk: float64(f.Severity)})

		case strings.HasPrefix(f.CheckID, "WL-01"): // privileged/root
			hostTarget := fmt.Sprintf("node/%s", f.Resource.Name)
			g.AddNode(&Node{ID: hostTarget, Type: NodeExternal, Name: "host-node", Risk: 4})
			g.AddEdge(Edge{From: resourceID, To: hostTarget, Type: EdgeNetworkAccess, Label: "host access", Risk: float64(f.Severity)})

		case strings.HasPrefix(f.CheckID, "WL-00"): // host namespace
			hostTarget := fmt.Sprintf("node/%s", f.Resource.Name)
			g.AddNode(&Node{ID: hostTarget, Type: NodeExternal, Name: "host-node", Risk: 4})
			g.AddEdge(Edge{From: resourceID, To: hostTarget, Type: EdgeNetworkAccess, Label: "host namespace", Risk: float64(f.Severity)})

		case strings.HasPrefix(f.CheckID, "SEC-"): // secrets in env
			secretTarget := fmt.Sprintf("%s/Secret/leaked", f.Resource.Namespace)
			g.AddNode(&Node{ID: secretTarget, Type: NodeSecret, Name: "exposed-secret", Namespace: f.Resource.Namespace, Risk: 3})
			g.AddEdge(Edge{From: resourceID, To: secretTarget, Type: EdgeMountSecret, Label: "secret exposure", Risk: float64(f.Severity)})
		}
	}

	return g
}
