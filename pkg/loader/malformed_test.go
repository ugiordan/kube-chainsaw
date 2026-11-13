package loader_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ugiordan/kube-chainsaw/pkg/loader"
)

func TestIndependentLoaderMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.yaml")
	require.NoError(t, os.WriteFile(path, []byte("kind: Pod\nmetadata: [broken"), 0600))
	_, err := loader.LoadManifests([]string{path}, nil)
	require.Error(t, err, "malformed input must not be silently accepted")
}
