export const createPolicyTarget = ({peer, configurationName, tunnelAddress = ""}) => ({
	configurationName,
	tunnelAddress,
	peer: {
		id: peer?.id || peer?.peer_public_key || "",
		name: peer?.name || peer?.peer_name || "",
		allowed_ip: peer?.allowed_ip || ""
	}
})
