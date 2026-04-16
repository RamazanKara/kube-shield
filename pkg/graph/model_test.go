package graph

import (
	"strings"
	"testing"
)

func TestSecurityGraph_AddNodeAndEdge(t *testing.T) {
	g := NewSecurityGraph()

	g.AddNode(&Node{ID: "pod-1", Type: NodePod, Name: "frontend", Namespace: "default"})
	g.AddNode(&Node{ID: "sa-1", Type: NodeServiceAccount, Name: "frontend-sa", Namespace: "default"})
	g.AddEdge(Edge{From: "pod-1", To: "sa-1", Type: EdgeUsesAccount})

	if len(g.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(g.Edges))
	}
}

func TestSecurityGraph_FindAttackPaths(t *testing.T) {
	g := NewSecurityGraph()

	// Build a simple attack path: External → Pod → SA → ClusterRole(cluster-admin) → Secret
	g.AddNode(&Node{ID: "ext", Type: NodeExternal, Name: "internet", Risk: 1.0})
	g.AddNode(&Node{ID: "pod-1", Type: NodePod, Name: "frontend", Namespace: "default", Risk: 0.8})
	g.AddNode(&Node{ID: "sa-1", Type: NodeServiceAccount, Name: "frontend-sa", Namespace: "default"})
	g.AddNode(&Node{ID: "cr-1", Type: NodeClusterRole, Name: "cluster-admin"})
	g.AddNode(&Node{ID: "secret-1", Type: NodeSecret, Name: "db-password", Namespace: "production"})

	g.AddEdge(Edge{From: "ext", To: "pod-1", Type: EdgeNetworkAccess, Risk: 0.9})
	g.AddEdge(Edge{From: "pod-1", To: "sa-1", Type: EdgeUsesAccount, Risk: 0.5})
	g.AddEdge(Edge{From: "sa-1", To: "cr-1", Type: EdgeBindsRole, Risk: 0.8})
	g.AddEdge(Edge{From: "sa-1", To: "secret-1", Type: EdgeMountSecret, Risk: 0.7})

	paths := g.FindAttackPaths(6)
	if len(paths) < 1 {
		t.Error("expected at least 1 attack path")
	}

	// Verify we found paths to targets
	foundSecretPath := false
	foundAdminPath := false
	for _, p := range paths {
		last := p.Nodes[len(p.Nodes)-1]
		if last.Type == NodeSecret {
			foundSecretPath = true
		}
		if last.Type == NodeClusterRole && last.Name == "cluster-admin" {
			foundAdminPath = true
		}
	}
	if !foundSecretPath {
		t.Error("expected to find attack path to secret")
	}
	if !foundAdminPath {
		t.Error("expected to find attack path to cluster-admin")
	}
}

func TestExportDOT(t *testing.T) {
	g := NewSecurityGraph()
	g.AddNode(&Node{ID: "pod-1", Type: NodePod, Name: "app"})
	g.AddNode(&Node{ID: "sa-1", Type: NodeServiceAccount, Name: "app-sa"})
	g.AddEdge(Edge{From: "pod-1", To: "sa-1", Type: EdgeUsesAccount})

	dot := g.ExportDOT()
	if !strings.Contains(dot, "digraph SecurityGraph") {
		t.Error("expected DOT output to contain digraph header")
	}
	if !strings.Contains(dot, "pod-1") {
		t.Error("expected DOT output to contain node pod-1")
	}
}

func TestRenderASCII_NoPaths(t *testing.T) {
	output := RenderASCII(nil)
	if !strings.Contains(output, "No attack paths") {
		t.Error("expected 'No attack paths' message")
	}
}

func TestRenderASCII_WithPaths(t *testing.T) {
	paths := []AttackPath{{
		Nodes: []*Node{
			{ID: "ext", Type: NodeExternal, Name: "internet"},
			{ID: "pod-1", Type: NodePod, Name: "app", Namespace: "default"},
			{ID: "secret-1", Type: NodeSecret, Name: "db-pass", Namespace: "default"},
		},
		Edges: []Edge{
			{From: "ext", To: "pod-1", Type: EdgeNetworkAccess},
			{From: "pod-1", To: "secret-1", Type: EdgeMountSecret},
		},
		Risk: 0.8,
	}}

	output := RenderASCII(paths)
	if !strings.Contains(output, "Path 1") {
		t.Error("expected path output")
	}
}
