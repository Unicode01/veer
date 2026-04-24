//go:build linux

package app

import "testing"

func TestDefaultDataplanePerfScenarioConfigUsesUDPSteadySmallPackets(t *testing.T) {
	t.Setenv(dataplanePerfProtocolEnv, "udp")
	t.Setenv(dataplanePerfTCPModeEnv, "")

	config := defaultDataplanePerfScenarioConfig(false)
	if config.Connections != 8192 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).Connections = %d, want 8192", config.Connections)
	}
	if config.Concurrency != 16 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).Concurrency = %d, want 16", config.Concurrency)
	}
	if config.BytesPerConnection != 64 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).BytesPerConnection = %d, want 64", config.BytesPerConnection)
	}
	if config.IOChunkBytes != 64 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).IOChunkBytes = %d, want 64", config.IOChunkBytes)
	}
	if config.SteadySeconds != 8 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).SteadySeconds = %d, want 8", config.SteadySeconds)
	}
}

func TestDefaultDataplanePerfScenarioConfigUsesLongerTCPUploadForDataplane(t *testing.T) {
	t.Setenv(dataplanePerfProtocolEnv, "tcp")
	t.Setenv(dataplanePerfTCPModeEnv, dataplanePerfTCPUploadMode)

	config := defaultDataplanePerfScenarioConfig(false)
	if config.Connections != 16 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).Connections = %d, want 16", config.Connections)
	}
	if config.Concurrency != 16 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).Concurrency = %d, want 16", config.Concurrency)
	}
	if config.BytesPerConnection != 256<<20 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).BytesPerConnection = %d, want %d", config.BytesPerConnection, 256<<20)
	}
	if config.IOChunkBytes != 128<<10 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).IOChunkBytes = %d, want %d", config.IOChunkBytes, 128<<10)
	}
	if config.SteadySeconds != 0 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(false).SteadySeconds = %d, want 0", config.SteadySeconds)
	}
}

func TestDefaultDataplanePerfScenarioConfigUsesLongerTCPUploadForEgressNAT(t *testing.T) {
	t.Setenv(dataplanePerfProtocolEnv, "tcp")
	t.Setenv(dataplanePerfTCPModeEnv, dataplanePerfTCPUploadMode)

	config := defaultDataplanePerfScenarioConfig(true)
	if config.Connections != 64 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(true).Connections = %d, want 64", config.Connections)
	}
	if config.Concurrency != 8 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(true).Concurrency = %d, want 8", config.Concurrency)
	}
	if config.BytesPerConnection != 32<<20 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(true).BytesPerConnection = %d, want %d", config.BytesPerConnection, 32<<20)
	}
	if config.IOChunkBytes != 16<<10 {
		t.Fatalf("defaultDataplanePerfScenarioConfig(true).IOChunkBytes = %d, want %d", config.IOChunkBytes, 16<<10)
	}
}

func TestDataplanePerfScenariosCarrySteadySeconds(t *testing.T) {
	scenarios := dataplanePerfScenarios(8192, 16, 64, 64, 8, 64<<10, 8)
	if len(scenarios) != 1 {
		t.Fatalf("dataplanePerfScenarios() len = %d, want 1", len(scenarios))
	}
	if scenarios[0].SteadySeconds != 8 {
		t.Fatalf("dataplanePerfScenarios()[0].SteadySeconds = %d, want 8", scenarios[0].SteadySeconds)
	}
}
