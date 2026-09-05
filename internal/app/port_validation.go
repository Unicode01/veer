package app

func validForwardPorts(inPort, outPort int) bool {
	return inPort >= 1 && inPort <= 65535 && outPort >= 1 && outPort <= 65535
}

func validatePortRangePorts(pr PortRange) string {
	if !validForwardPorts(pr.StartPort, pr.OutStartPort) || pr.EndPort < 1 || pr.EndPort > 65535 {
		return "ports must be between 1 and 65535"
	}
	if pr.StartPort > pr.EndPort {
		return "start_port must be <= end_port"
	}
	// Subtract only after validating every operand, including persisted/IPC values.
	if pr.EndPort-pr.StartPort > 65535-pr.OutStartPort {
		return "outbound port range must end at or below 65535"
	}
	return ""
}
