package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/kube-shield/v2/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestCompletionSkipsConfiguration(t *testing.T) {
	oldCfgFile := cfgFile
	t.Cleanup(func() { cfgFile = oldCfgFile })
	cfgFile = filepath.Join(t.TempDir(), "missing.yaml")
	cmd := &cobra.Command{Use: cobra.ShellCompRequestCmd}
	if err := rootCmd.PersistentPreRunE(cmd, nil); err != nil {
		t.Fatalf("completion tried to load configuration: %v", err)
	}
}

func TestInitConfig(t *testing.T) {
	for _, tt := range []struct {
		name, homeConfig, localConfig, explicitConfig, envNamespace, wantNamespace, wantErr string
		explicit                                                                            bool
	}{
		{name: "optional config absent"},
		{name: "home precedes local", homeConfig: "namespace: home", localConfig: "namespace: local", wantNamespace: "home"},
		{name: "local fallback", localConfig: "namespace: local", wantNamespace: "local"},
		{name: "explicit overrides discovery", homeConfig: "namespace: home", explicit: true, explicitConfig: "namespace: explicit", wantNamespace: "explicit"},
		{name: "environment overrides file", localConfig: "namespace: local", envNamespace: "environment", wantNamespace: "environment"},
		{name: "missing explicit file", explicit: true, wantErr: "failed to read config"},
		{name: "malformed explicit file", explicit: true, explicitConfig: "namespace: [", wantErr: "failed to read config"},
		{name: "malformed discovered file", localConfig: "namespace: [", wantErr: "failed to read config"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			oldCfgFile := cfgFile
			t.Cleanup(func() { cfgFile = oldCfgFile })
			cfgFile = ""
			home := t.TempDir()
			local := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("KUBE_SHIELD_NAMESPACE", tt.envNamespace)
			t.Chdir(local)
			for path, data := range map[string]string{
				filepath.Join(home, ".kube-shield.yaml"):  tt.homeConfig,
				filepath.Join(local, ".kube-shield.yaml"): tt.localConfig,
				filepath.Join(local, "explicit.yaml"):     tt.explicitConfig,
			} {
				if data != "" {
					if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tt.explicit {
				cfgFile = filepath.Join(local, "explicit.yaml")
			}
			err := rootCmd.PersistentPreRunE(rootCmd, nil)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := config.Load().Namespace; got != tt.wantNamespace {
				t.Errorf("namespace = %q, want %q", got, tt.wantNamespace)
			}
		})
	}
}
