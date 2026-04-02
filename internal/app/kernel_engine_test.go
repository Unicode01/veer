package app

import (
	"reflect"
	"testing"
)

func TestDefaultKernelEngineOrder(t *testing.T) {
	got := defaultKernelEngineOrder()
	want := []string{kernelEngineTC}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaultKernelEngineOrder() = %v, want %v", got, want)
	}
}
