const singleHostAddresses = (allowedIp) => String(allowedIp || "")
	.split(",")
	.map(value => value.trim())
	.filter(value => /\/(32|128)$/.test(value))
	.map(value => value.replace(/\/(32|128)$/, ""));

export const createPolicyTarget = ({peer, configurationName, tunnelAddress = "", tunnelAddresses = []}) => ({
	configurationName,
	tunnelAddress,
	tunnelAddresses: [...new Set([
		...tunnelAddresses,
		...singleHostAddresses(peer?.allowed_ip)
	])],
	peer: {
		id: peer?.id || peer?.peer_public_key || "",
		name: peer?.name || peer?.peer_name || "",
		allowed_ip: peer?.allowed_ip || ""
	}
})
