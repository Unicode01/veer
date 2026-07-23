package app

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/dop251/goja"
)

const (
	pluginControlModuleMaxCount        = 128
	pluginControlModuleMaxBytes        = 256 << 10
	pluginControlModuleMaxTotalBytes   = 8 << 20
	pluginHostInternalModuleLoadMethod = "__veer.module.load"
)

type pluginControlModuleSource struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

type pluginControlModuleResolver func(referrer, request string) (pluginControlModuleSource, error)

type pluginControlModuleLoader struct {
	runtime     *goja.Runtime
	resolver    pluginControlModuleResolver
	modules     map[string]*goja.Object
	resolutions map[string]string
	totalBytes  int
}

func installPluginControlModuleLoader(runtime *goja.Runtime, mainID string, mainModule *goja.Object, resolver pluginControlModuleResolver) error {
	if runtime == nil || mainModule == nil || resolver == nil {
		return fmt.Errorf("plugin control module loader is unavailable")
	}
	mainID, err := normalizePluginControlModuleID(mainID)
	if err != nil {
		return fmt.Errorf("control.main module id: %w", err)
	}
	loader := &pluginControlModuleLoader{
		runtime:     runtime,
		resolver:    resolver,
		modules:     map[string]*goja.Object{mainID: mainModule},
		resolutions: make(map[string]string),
	}
	return runtime.Set("require", loader.requireFrom(mainID))
}

func (loader *pluginControlModuleLoader) requireFrom(referrer string) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 1 {
			panic(loader.runtime.NewTypeError("require expects exactly one relative module path"))
		}
		request := strings.TrimSpace(call.Arguments[0].String())
		value, err := loader.load(referrer, request)
		if err != nil {
			panic(loader.runtime.NewGoError(err))
		}
		return value
	}
}

func (loader *pluginControlModuleLoader) load(referrer, request string) (goja.Value, error) {
	if loader == nil || loader.runtime == nil || loader.resolver == nil {
		return nil, fmt.Errorf("plugin control module loader is unavailable")
	}
	resolutionKey := referrer + "\x00" + request
	if moduleID := loader.resolutions[resolutionKey]; moduleID != "" {
		if module := loader.modules[moduleID]; module != nil {
			return module.Get("exports"), nil
		}
	}
	source, err := loader.resolver(referrer, request)
	if err != nil {
		return nil, err
	}
	source.ID, err = normalizePluginControlModuleID(source.ID)
	if err != nil {
		return nil, fmt.Errorf("resolved module id: %w", err)
	}
	loader.resolutions[resolutionKey] = source.ID
	if module := loader.modules[source.ID]; module != nil {
		return module.Get("exports"), nil
	}
	if len(loader.modules)-1 >= pluginControlModuleMaxCount {
		return nil, fmt.Errorf("plugin control module limit reached: %d", pluginControlModuleMaxCount)
	}
	if len(source.Source) > pluginControlModuleMaxBytes {
		return nil, fmt.Errorf("plugin control module %s exceeds %d bytes", source.ID, pluginControlModuleMaxBytes)
	}
	if loader.totalBytes+len(source.Source) > pluginControlModuleMaxTotalBytes {
		return nil, fmt.Errorf("plugin control modules exceed %d total bytes", pluginControlModuleMaxTotalBytes)
	}

	exports := loader.runtime.NewObject()
	module := loader.runtime.NewObject()
	if err := module.Set("exports", exports); err != nil {
		return nil, err
	}
	loader.modules[source.ID] = module
	loader.totalBytes += len(source.Source)
	loaded := false
	defer func() {
		if !loaded {
			delete(loader.modules, source.ID)
			loader.totalBytes -= len(source.Source)
		}
	}()

	wrapper := "(function(exports,module,require,__filename,__dirname){\n" + source.Source + "\n})"
	value, err := loader.runtime.RunScript(source.ID, wrapper)
	if err != nil {
		return nil, fmt.Errorf("compile plugin module %s: %w", source.ID, err)
	}
	function, ok := goja.AssertFunction(value)
	if !ok {
		return nil, fmt.Errorf("plugin module %s did not compile to a function", source.ID)
	}
	if _, err := function(
		goja.Undefined(),
		exports,
		module,
		loader.runtime.ToValue(loader.requireFrom(source.ID)),
		loader.runtime.ToValue(source.ID),
		loader.runtime.ToValue(path.Dir(source.ID)),
	); err != nil {
		return nil, fmt.Errorf("run plugin module %s: %w", source.ID, err)
	}
	loaded = true
	return module.Get("exports"), nil
}

func pluginControlMainModuleID(plugin LoadedPlugin) (string, error) {
	if plugin.controlMainPath == "" || plugin.rootDir == "" {
		mainID := ""
		if plugin.Control != nil {
			mainID = plugin.Control.Main
		}
		if mainID == "" && plugin.controlMainPath != "" {
			mainID = filepath.Base(plugin.controlMainPath)
		}
		if mainID != "" {
			return normalizePluginControlModuleID(filepath.ToSlash(mainID))
		}
		return "", errPluginRuntimeTargetNotLoaded
	}
	realRoot, err := pluginControlRealRoot(plugin)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(realRoot, plugin.controlMainPath)
	if err != nil {
		return "", fmt.Errorf("resolve control.main module id: %w", err)
	}
	return normalizePluginControlModuleID(filepath.ToSlash(relative))
}

func resolvePluginControlModule(plugin LoadedPlugin, referrer, request string) (pluginControlModuleSource, error) {
	referrer, err := normalizePluginControlModuleID(referrer)
	if err != nil {
		return pluginControlModuleSource{}, fmt.Errorf("invalid module referrer: %w", err)
	}
	request = strings.TrimSpace(request)
	if request == "" || strings.ContainsRune(request, '\x00') || strings.Contains(request, "\\") || path.IsAbs(request) ||
		(!strings.HasPrefix(request, "./") && !strings.HasPrefix(request, "../")) {
		return pluginControlModuleSource{}, fmt.Errorf("require path must be relative to the current plugin module")
	}
	base := path.Clean(path.Join(path.Dir(referrer), request))
	if base == "." || base == ".." || strings.HasPrefix(base, "../") {
		return pluginControlModuleSource{}, fmt.Errorf("required module escapes the plugin root")
	}
	candidates := []string{base}
	switch extension := path.Ext(base); extension {
	case "":
		candidates = []string{base + ".js", path.Join(base, "index.js")}
	case ".js":
	default:
		return pluginControlModuleSource{}, fmt.Errorf("plugin control modules must use the .js extension")
	}

	realRoot, err := pluginControlRealRoot(plugin)
	if err != nil {
		return pluginControlModuleSource{}, err
	}
	for _, candidate := range candidates {
		candidate, err = normalizePluginControlModuleID(candidate)
		if err != nil {
			return pluginControlModuleSource{}, err
		}
		candidatePath := filepath.Join(realRoot, filepath.FromSlash(candidate))
		if !pathWithinRoot(realRoot, candidatePath) {
			return pluginControlModuleSource{}, fmt.Errorf("required module escapes the plugin root")
		}
		realPath, evalErr := filepath.EvalSymlinks(candidatePath)
		if evalErr != nil {
			if os.IsNotExist(evalErr) {
				continue
			}
			return pluginControlModuleSource{}, fmt.Errorf("resolve plugin module %s: %w", candidate, evalErr)
		}
		if !pathWithinRoot(realRoot, realPath) {
			return pluginControlModuleSource{}, fmt.Errorf("required module escapes the plugin root")
		}
		realRelative, relErr := filepath.Rel(realRoot, realPath)
		if relErr != nil {
			return pluginControlModuleSource{}, relErr
		}
		data, fileInfo, readErr := readPluginRootedRegularFile(realRoot, filepath.ToSlash(realRelative), pluginControlModuleMaxBytes)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			if fileInfo != nil && !fileInfo.Mode().IsRegular() {
				continue
			}
			return pluginControlModuleSource{}, fmt.Errorf("read plugin module %s: %w", candidate, readErr)
		}
		moduleID, normalizeErr := normalizePluginControlModuleID(filepath.ToSlash(realRelative))
		if normalizeErr != nil {
			return pluginControlModuleSource{}, normalizeErr
		}
		return pluginControlModuleSource{ID: moduleID, Source: string(data)}, nil
	}
	return pluginControlModuleSource{}, fmt.Errorf("plugin control module %q was not found from %s", request, referrer)
}

func pluginControlRealRoot(plugin LoadedPlugin) (string, error) {
	root, err := filepath.Abs(plugin.rootDir)
	if err != nil {
		return "", fmt.Errorf("resolve plugin root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve plugin root: %w", err)
	}
	return realRoot, nil
}

func normalizePluginControlModuleID(value string) (string, error) {
	value = strings.TrimSpace(value)
	nativePath := filepath.FromSlash(value)
	if value == "" || strings.ContainsRune(value, '\x00') || strings.Contains(value, "\\") || path.IsAbs(value) ||
		filepath.IsAbs(nativePath) || filepath.VolumeName(nativePath) != "" {
		return "", fmt.Errorf("module id must be a plugin-relative POSIX path")
	}
	value = path.Clean(value)
	if value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return "", fmt.Errorf("module id escapes the plugin root")
	}
	if path.Ext(value) != ".js" {
		return "", fmt.Errorf("module id must use the .js extension")
	}
	return value, nil
}

func pluginHostMethodAllowed(method string) bool {
	if method == pluginHostInternalModuleLoadMethod {
		return true
	}
	_, allowed := pluginHostControlMethodSet[method]
	return allowed
}
