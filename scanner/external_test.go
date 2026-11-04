package scanner_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestImportFromAnotherModule(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module scanner-consumer\n\ngo 1.26.0\n\nrequire github.com/git-pkgs/secrets v0.0.0\n\nreplace github.com/git-pkgs/secrets => " + root + "\n",
		"main.go": `package main
import (
 "context"
 "fmt"
 "github.com/git-pkgs/secrets/scanner"
)
func main() {
 s, err := scanner.New(context.Background(), scanner.Options{})
 if err != nil { panic(err) }
 defer s.Close()
 for _, blob := range []struct { data, path, rule string }{
  {"token: ` + token + `\n", "config.yml", "github-pat"},
  {"\x00binary", "certs/client.p12", "pkcs12-file"},
 } {
  result, err := s.Scan(context.Background(), []byte(blob.data), blob.path)
  if err != nil { panic(err) }
  if len(result.Findings) != 1 || result.Findings[0].RuleID != blob.rule { panic("missing finding") }
 }
 fmt.Println("blob scanner imported and detected both fixtures")
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-mod=mod", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("external consumer: %v\n%s", err, output)
	}
}
