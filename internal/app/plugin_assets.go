package app

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func resolvePluginAssets(plugin *LoadedPlugin) error {
	if plugin.UI == nil || plugin.UI.StaticDir == "" {
		return nil
	}
	staticDir := filepath.Join(plugin.rootDir, filepath.FromSlash(plugin.UI.StaticDir))
	cleanRoot, err := filepath.Abs(plugin.rootDir)
	if err != nil {
		return fmt.Errorf("resolve plugin root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return fmt.Errorf("resolve plugin root: %w", err)
	}
	cleanStatic, err := filepath.Abs(staticDir)
	if err != nil {
		return fmt.Errorf("resolve static_dir: %w", err)
	}
	if !pathWithinRoot(cleanRoot, cleanStatic) {
		return fmt.Errorf("ui.static_dir escapes plugin root")
	}
	realStatic, err := filepath.EvalSymlinks(cleanStatic)
	if err != nil {
		return fmt.Errorf("ui.static_dir: %w", err)
	}
	if !pathWithinRoot(realRoot, realStatic) {
		return fmt.Errorf("ui.static_dir escapes plugin root")
	}
	info, err := os.Stat(realStatic)
	if err != nil {
		return fmt.Errorf("ui.static_dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("ui.static_dir is not a directory")
	}
	if plugin.UI.Entry != "" {
		entryPath := filepath.Join(realStatic, filepath.FromSlash(plugin.UI.Entry))
		if !pathWithinRoot(realStatic, entryPath) {
			return fmt.Errorf("ui.entry escapes static_dir")
		}
		realEntry, err := filepath.EvalSymlinks(entryPath)
		if err != nil {
			return fmt.Errorf("ui.entry: %w", err)
		}
		if !pathWithinRoot(realStatic, realEntry) {
			return fmt.Errorf("ui.entry escapes static_dir")
		}
		entryInfo, err := os.Stat(realEntry)
		if err != nil {
			return fmt.Errorf("ui.entry: %w", err)
		}
		if entryInfo.IsDir() {
			return fmt.Errorf("ui.entry is a directory")
		}
		got, err := sha256File(realEntry)
		if err != nil {
			return fmt.Errorf("hash ui.entry: %w", err)
		}
		plugin.UI.ResolvedSHA256 = got
		if pluginUISHA256Required(*plugin) && plugin.UI.SHA256 == "" {
			return fmt.Errorf("ui.sha256 is required for stable or preview UI entry files")
		}
		if plugin.UI.SHA256 != "" && plugin.UI.SHA256 != got {
			return fmt.Errorf("ui.sha256 mismatch")
		}
	}
	plugin.staticDir = realStatic
	plugin.AssetBasePath = "/api/plugins/" + plugin.ID + "/assets/"
	return nil
}

func pluginUISHA256Required(plugin LoadedPlugin) bool {
	if plugin.Builtin || plugin.UI == nil || plugin.UI.Entry == "" {
		return false
	}
	switch strings.TrimSpace(strings.ToLower(plugin.Stability)) {
	case pluginStabilityStable, pluginStabilityPreview:
		return true
	default:
		return false
	}
}

func handlePluginAsset(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	const apiPluginPrefix = "/api/plugins/"
	rest := strings.TrimPrefix(r.URL.Path, apiPluginPrefix)
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[1] != "assets" || !pluginIDPattern.MatchString(parts[0]) {
		http.NotFound(w, r)
		return
	}

	id := parts[0]
	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	if pm != nil {
		catalog = pm.pluginCatalogWithConfig(cfg)
	}
	for _, plugin := range catalog.Plugins {
		if plugin.ID != id || plugin.Status != pluginStatusActive || plugin.staticDir == "" || plugin.AssetBasePath == "" {
			continue
		}
		pluginAssetHandler(plugin.AssetBasePath, plugin.staticDir).ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func pluginAssetHandler(prefix, staticDir string) http.Handler {
	fileServer := http.StripPrefix(prefix, http.FileServer(newPluginStaticFileSystem(staticDir)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fileServer.ServeHTTP(w, r)
	})
}

type pluginStaticFileSystem struct {
	root     string
	realRoot string
}

func newPluginStaticFileSystem(root string) pluginStaticFileSystem {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		absRoot = root
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		realRoot = absRoot
	}
	return pluginStaticFileSystem{root: absRoot, realRoot: realRoot}
}

func (p pluginStaticFileSystem) Open(name string) (http.File, error) {
	cleanName := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(name, "/")), "/")
	if cleanName == "." {
		cleanName = ""
	}
	filePath := filepath.Join(p.root, filepath.FromSlash(cleanName))
	realPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return nil, err
	}
	if !pathWithinRoot(p.realRoot, realPath) {
		return nil, os.ErrPermission
	}

	file, err := os.Open(realPath)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.IsDir() {
		return file, nil
	}

	indexPath := filepath.Join(realPath, "index.html")
	if !pathWithinRoot(p.realRoot, indexPath) {
		_ = file.Close()
		return nil, os.ErrPermission
	}
	index, err := os.Open(indexPath)
	if err != nil {
		_ = file.Close()
		return nil, os.ErrNotExist
	}
	_ = index.Close()
	return file, nil
}
