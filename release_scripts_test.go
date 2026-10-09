package main

import (
	"crypto/sha256"
	"fmt"
	"go.yaml.in/yaml/v3"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func releaseFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"bash", "git", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s required", tool)
		}
	}
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"ci_release_common.sh", "ci_release_notes.sh", "ci_upload_release_packages.sh", "ci_publish_release.sh"} {
		data, err := os.ReadFile(filepath.Join("scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		write("scripts/"+name, string(data))
	}
	write("VERSION", "1.2.3\n")
	write("dist/release_notes.md", "Release notes\n")
	name := "ssl-toolbox-1.2.3-linux-amd64.tar.gz"
	write("dist/release/"+name, "test archive")
	write("dist/release/SHA256SUMS", fmt.Sprintf("%x  %s\n", sha256.Sum256([]byte("test archive")), name))

	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "ci@example.com"}, {"config", "user.name", "Release test"}, {"add", "."}, {"commit", "-qm", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %s: %v", out, err)
		}
	}
	return dir
}

func runReleaseScript(dir, name string, env ...string) (string, error) {
	cmd := exec.Command("bash", "scripts/"+name)
	cmd.Dir = dir
	// Do not let CI metadata or publishing credentials leak into fixtures.
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		if strings.HasPrefix(key, "CI_") || strings.HasPrefix(key, "GITHUB_") || strings.HasPrefix(key, "GH_") || strings.HasPrefix(key, "RELEASE_") {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "PATH="+filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestGitLabPackageUpload(t *testing.T) {
	dir := releaseFixture(t)
	var uploads []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != "PUT" || r.Header.Get("JOB-TOKEN") != "test" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(403)
			return
		}
		uploads = append(uploads, filepath.Base(r.URL.Path))
		w.WriteHeader(201)
	}))
	defer server.Close()
	out, err := runReleaseScript(dir, "ci_upload_release_packages.sh", "CI_API_V4_URL="+server.URL, "CI_PROJECT_ID=1", "CI_JOB_TOKEN=test")
	if err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	list, err := os.ReadFile(filepath.Join(dir, "dist/release_assets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(uploads) != 2 || string(list) != strings.Join(uploads, "\n")+"\n" {
		t.Fatalf("uploads=%v assets=%s", uploads, list)
	}
}

func TestGitLabRejectsUnauthorizedAPI(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq required")
	}
	dir := releaseFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "dist/release_assets.txt"), []byte("SHA256SUMS\n"), 0644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected write: %s", r.Method)
		}
		w.WriteHeader(403)
	}))
	defer server.Close()
	out, err := runReleaseScript(dir, "ci_publish_release.sh", "CI_API_V4_URL="+server.URL, "CI_PROJECT_ID=1", "CI_JOB_TOKEN=test")
	if err == nil || !strings.Contains(out, "HTTP 403") {
		t.Fatalf("out=%s err=%v", out, err)
	}
}

func TestGitLabReleaseCreationAndRetry(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq required")
	}
	dir := releaseFixture(t)
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	sha, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.TrimSpace(string(sha))
	if err := os.WriteFile(filepath.Join(dir, "dist/release_assets.txt"), []byte("SHA256SUMS\n"), 0644); err != nil {
		t.Fatal(err)
	}
	created, linked := false, false
	posts, updates := 0, 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("JOB-TOKEN") != "test" {
			t.Error("missing token")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/assets/links"):
			if linked {
				fmt.Fprint(w, `[{"id":1,"name":"SHA256SUMS"}]`)
			} else {
				fmt.Fprint(w, `[]`)
			}
		case r.Method == "GET":
			if !created {
				w.WriteHeader(404)
			} else {
				fmt.Fprintf(w, `{"commit":{"id":%q}}`, commit)
			}
		case r.Method == "POST":
			posts++
			if strings.Contains(r.URL.Path, "/assets/links") {
				linked = true
			} else {
				created = true
			}
			fmt.Fprint(w, `{}`)
		case r.Method == "PUT":
			updates++
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(405)
		}
	}))
	defer server.Close()
	for i := 0; i < 2; i++ {
		out, err := runReleaseScript(dir, "ci_publish_release.sh", "CI_API_V4_URL="+server.URL, "CI_PROJECT_ID=1", "CI_JOB_TOKEN=test")
		if err != nil {
			t.Fatalf("%s: %v", out, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 2 || updates != 2 {
		t.Fatalf("posts=%d updates=%d", posts, updates)
	}
}

func TestReleaseNotesMetadata(t *testing.T) {
	dir := releaseFixture(t)
	if out, err := runReleaseScript(dir, "ci_release_notes.sh"); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "dist/release.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RELEASE_VERSION=1.2.3", "RELEASE_TAG=v1.2.3", "RELEASE_COMMIT="} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %s: %s", want, data)
		}
	}
}

func TestReleaseRejectsRetagAndBadMetadata(t *testing.T) {
	for _, scenario := range []string{"version", "tag", "commit", "existing-tag"} {
		t.Run(scenario, func(t *testing.T) {
			dir := releaseFixture(t)
			env := []string{}
			switch scenario {
			case "version":
				env = append(env, "RELEASE_VERSION=9.9.9")
			case "tag":
				env = append(env, "RELEASE_TAG=v9.9.9")
			case "commit":
				env = append(env, "RELEASE_COMMIT=not-a-commit")
			case "existing-tag":
				for _, args := range [][]string{{"tag", "v1.2.3"}, {"commit", "--allow-empty", "-qm", "new commit"}} {
					cmd := exec.Command("git", args...)
					cmd.Dir = dir
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("git: %s %v", out, err)
					}
				}
			}
			if out, err := runReleaseScript(dir, "ci_release_notes.sh", env...); err == nil {
				t.Fatalf("accepted %s: %s", scenario, out)
			}
		})
	}
}

func TestReleaseUploadRejectsCorruption(t *testing.T) {
	dir := releaseFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "dist/release/ssl-toolbox-1.2.3-linux-amd64.tar.gz"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(201) }))
	defer server.Close()
	if out, err := runReleaseScript(dir, "ci_upload_release_packages.sh", "CI_API_V4_URL="+server.URL, "CI_PROJECT_ID=1", "CI_JOB_TOKEN=test"); err == nil {
		t.Fatalf("corruption accepted: %s", out)
	}
	if requests != 0 {
		t.Fatal("uploaded corrupted archive")
	}
}

func TestReleasePipelineConfiguration(t *testing.T) {
	data, err := os.ReadFile(".gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Default struct {
			Image string `yaml:"image"`
		} `yaml:"default"`
		Variables    map[string]string `yaml:"variables"`
		ReleaseRules struct {
			Rules []struct {
				If      string   `yaml:"if"`
				Changes []string `yaml:"changes"`
			} `yaml:"rules"`
		} `yaml:".release_rules"`
		Binaries struct {
			Needs []struct {
				Job       string `yaml:"job"`
				Artifacts bool   `yaml:"artifacts"`
			} `yaml:"needs"`
			Artifacts struct {
				Paths []string `yaml:"paths"`
			} `yaml:"artifacts"`
		} `yaml:"release_binaries"`
		Publish struct {
			ResourceGroup string `yaml:"resource_group"`
			Needs         []struct {
				Job       string `yaml:"job"`
				Artifacts bool   `yaml:"artifacts"`
			} `yaml:"needs"`
		} `yaml:"publish_release"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(config.Default.Image, "golang:") || config.Variables["GIT_DEPTH"] != "0" {
		t.Fatal("not a direct Go build with full tag history")
	}
	if len(config.ReleaseRules.Rules) != 2 || len(config.ReleaseRules.Rules[1].Changes) != 1 || config.ReleaseRules.Rules[1].Changes[0] != "VERSION" {
		t.Fatal("VERSION/manual release rules missing")
	}
	checks := map[string]bool{}
	for _, need := range config.Binaries.Needs {
		checks[need.Job] = true
	}
	if !checks["check"] || !checks["test"] || !checks["release_notes"] {
		t.Fatal("release bypasses verification")
	}
	if len(config.Binaries.Artifacts.Paths) != 1 || config.Binaries.Artifacts.Paths[0] != "dist/release_assets.txt" {
		t.Fatal("archives should be uploaded to Package Registry, not temporary job artifacts")
	}
	if config.Publish.ResourceGroup != "release" || len(config.Publish.Needs) != 2 {
		t.Fatal("missing serialized publication or release metadata")
	}
}

func TestGitLabRejectsReleaseTagConflict(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq required")
	}
	dir := releaseFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "dist/release_assets.txt"), []byte("SHA256SUMS\n"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected write: %s", r.Method)
		}
		fmt.Fprintf(w, `{"commit":{"id":%q}}`, strings.Repeat("0", 40))
	}))
	defer server.Close()
	if out, err := runReleaseScript(dir, "ci_publish_release.sh", "CI_API_V4_URL="+server.URL, "CI_PROJECT_ID=1", "CI_JOB_TOKEN=test"); err == nil || !strings.Contains(out, "different commit") {
		t.Fatalf("tag overwrite allowed: %s %v", out, err)
	}
}
