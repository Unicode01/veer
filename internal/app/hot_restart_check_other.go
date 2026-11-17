//go:build !linux

package app

import "errors"

func inspectHotRestart(hotRestartCheckOptions) (hotRestartCheckReport, error) {
	return hotRestartCheckReport{}, errors.New("hot restart is Linux-only")
}
