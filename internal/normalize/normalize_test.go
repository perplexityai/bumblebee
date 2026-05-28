package normalize

import "testing"

func TestNPM(t *testing.T) {
	cases := map[string]string{
		"Lodash":               "lodash",
		"@TanStack/Query-Core": "@tanstack/query-core",
		"  @Scope/Name  ":      "@scope/name",
		"react":                "react",
	}
	for in, want := range cases {
		if got := NPM(in); got != want {
			t.Errorf("NPM(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConda(t *testing.T) {
	cases := map[string]string{
		"NumPy":           "numpy",
		"python-dateutil": "python-dateutil",
		"  PyTorch-CPU  ": "pytorch-cpu",
		"libstdcxx-ng":    "libstdcxx-ng",
		"pytorch-mutex":   "pytorch-mutex",
		"_libgcc_mutex":   "_libgcc_mutex",
		"OpenSSL":         "openssl",
	}
	for in, want := range cases {
		if got := Conda(in); got != want {
			t.Errorf("Conda(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPyPI(t *testing.T) {
	cases := map[string]string{
		"Flask":                  "flask",
		"Pillow":                 "pillow",
		"requests_oauthlib":      "requests-oauthlib",
		"zope.interface":         "zope-interface",
		"PyYAML":                 "pyyaml",
		"foo___bar.baz--qux":     "foo-bar-baz-qux",
		"  Some_Pkg  ":           "some-pkg",
		"-leading-and-trailing-": "leading-and-trailing",
	}
	for in, want := range cases {
		if got := PyPI(in); got != want {
			t.Errorf("PyPI(%q) = %q, want %q", in, got, want)
		}
	}
}
