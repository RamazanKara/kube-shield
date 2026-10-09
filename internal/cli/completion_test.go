package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestFlagCompletions(t *testing.T) {
	for _, tt := range []struct {
		name         string
		cmd          *cobra.Command
		flag, prefix string
		want         []string
	}{
		{"output", rootCmd, "output", "m", []string{"markdown"}},
		{"rules output", rulesCmd, "output", "", []string{"table", "json"}},
		{"severity", scanCmd, "severity", "h", []string{"high"}},
		{"provider", rootCmd, "ai-provider", "o", []string{"openai", "ollama"}},
		{"scanner list", scanCmd, "scanners", "workload,r", []string{"workload,rbac"}},
		{"scanner duplicate", scanCmd, "scanners", "rbac,r", nil},
		{"scanner uppercase", scanCmd, "scanners", "RBAC,R", nil},
		{"category list", scanCmd, "category", "cis,se", []string{"cis,secrets"}},
		{"dashboard", dashboardCmd, "scanners", "net", []string{"netpol"}},
		{"unknown", scanCmd, "severity", "z", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			complete, ok := tt.cmd.GetFlagCompletionFunc(tt.flag)
			if !ok {
				t.Fatal("completion not registered")
			}
			got, directive := complete(tt.cmd, nil, tt.prefix)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
			if directive != cobra.ShellCompDirectiveNoFileComp {
				t.Errorf("unexpected directive: %d", directive)
			}
		})
	}
}

func TestRuleCompletion(t *testing.T) {
	for _, tt := range []struct {
		prefix string
		args   []string
		want   bool
	}{
		{"WL-010", nil, true}, {"wl-010", nil, true}, {"unknown", nil, false}, {"", []string{"WL-010"}, false},
	} {
		t.Run(tt.prefix+strings.Join(tt.args, ""), func(t *testing.T) {
			got, directive := rulesShowCmd.ValidArgsFunction(rulesShowCmd, tt.args, tt.prefix)
			if (len(got) > 0) != tt.want {
				t.Fatalf("unexpected completions: %v", got)
			}
			if tt.want && !strings.HasPrefix(got[0], "WL-010\t") {
				t.Fatal(got)
			}
			if directive != cobra.ShellCompDirectiveNoFileComp {
				t.Fatal(directive)
			}
		})
	}
}

func FuzzCompleteValues(f *testing.F) {
	for _, seed := range []string{"", "rbac,", "rbac,r", ",,", "RBAC,s"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, prefix string) {
		got, directive := completeValues([]string{"rbac", "secrets"}, true)(nil, nil, prefix)
		if directive != cobra.ShellCompDirectiveNoFileComp {
			t.Fatal(directive)
		}
		for _, match := range got {
			if !strings.HasPrefix(strings.ToLower(match), strings.ToLower(prefix)) {
				t.Fatalf("%q does not complete %q", match, prefix)
			}
		}
	})
}
