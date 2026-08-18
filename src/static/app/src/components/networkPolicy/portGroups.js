const PORT_MIN = 1;
const PORT_MAX = 65535;

const asInteger = (value) => {
	if (value === null || value === undefined || value === "") return null;
	const number = Number(value);
	return Number.isInteger(number) ? number : value;
};

const normalizeProtocol = (protocol) => String(protocol || "tcp").toLowerCase();

const normalizePort = (port = {}) => {
	const from = asInteger(port.from);
	const to = port.to === null || port.to === undefined || port.to === ""
		? from
		: asInteger(port.to);
	return {from, to, showRange: Boolean(port.showRange || (from !== null && to !== from))};
};

const portSort = (left, right) => {
	const leftFrom = Number.isInteger(left.from) ? left.from : Number.MAX_SAFE_INTEGER;
	const rightFrom = Number.isInteger(right.from) ? right.from : Number.MAX_SAFE_INTEGER;
	if (leftFrom !== rightFrom) return leftFrom - rightFrom;
	const leftTo = Number.isInteger(left.to) ? left.to : Number.MAX_SAFE_INTEGER;
	const rightTo = Number.isInteger(right.to) ? right.to : Number.MAX_SAFE_INTEGER;
	return leftTo - rightTo;
};

const groupSort = (left, right) => {
	const destinationOrder = left.destination.localeCompare(right.destination);
	if (destinationOrder !== 0) return destinationOrder;
	return left.protocol.localeCompare(right.protocol);
};

export const portGroupKey = (destination, protocol) => `${destination}\u0000${normalizeProtocol(protocol)}`;

export const emptyPort = () => ({from: null, to: null, showRange: false});

export const emptyPortGroup = () => ({
	destination: "",
	protocol: "tcp",
	ports: [emptyPort()],
	allPorts: false
});

export const normalizePortGroup = (group = {}) => {
	const protocol = normalizeProtocol(group.protocol);
	const ports = Array.isArray(group.ports) ? group.ports.map(normalizePort).sort(portSort) : [];
	return {
		destination: String(group.destination || "").trim(),
		protocol,
		ports: protocol === "icmp" ? [] : ports,
		allPorts: protocol !== "icmp" && Boolean(group.allPorts)
	};
};

export const groupRules = (rules = []) => {
	const groups = new Map();
	for (const rule of Array.isArray(rules) ? rules : []){
		const destination = String(rule?.destination || "").trim();
		const protocol = normalizeProtocol(rule?.protocol);
		const key = portGroupKey(destination, protocol);
		if (!groups.has(key)){
			groups.set(key, {destination, protocol, ports: [], allPorts: false});
		}
		const group = groups.get(key);
		if (protocol !== "icmp" && rule?.ports === null){
			group.allPorts = true;
		}else if (protocol !== "icmp"){
			group.ports.push(normalizePort(rule?.ports));
		}
	}
	return [...groups.values()].map(normalizePortGroup).sort(groupSort);
};

export const flattenGroups = (groups = []) => {
	return (Array.isArray(groups) ? groups : [])
		.map(normalizePortGroup)
		.sort(groupSort)
		.flatMap((group) => {
			if (group.protocol === "icmp" || group.allPorts){
				return [{destination: group.destination, protocol: group.protocol, ports: null}];
			}
			return group.ports.map((port) => ({
				destination: group.destination,
				protocol: group.protocol,
				ports: {from: port.from, to: port.to}
			}));
		});
};

export const validatePortGroup = (group) => {
	const normalized = normalizePortGroup(group);
	const ports = Array.isArray(group?.ports) ? group.ports.map(normalizePort) : [];
	const portErrors = ports.map(() => "");
	let groupError = "";

	if (!normalized.destination){
		groupError = "Enter a destination IP or CIDR.";
	}
	if (normalized.protocol === "icmp"){
		return {groupError, portErrors};
	}
	if (normalized.allPorts){
	if (ports.length){
			groupError = "All ports cannot be combined with specific ports.";
		}
		return {groupError, portErrors};
	}
	if (!ports.length){
		return {groupError: groupError || "Add at least one port.", portErrors};
	}

	for (const [index, port] of ports.entries()){
		if (!Number.isInteger(port.from) || port.from < PORT_MIN || port.from > PORT_MAX){
			portErrors[index] = "Enter a port from 1 to 65535.";
			continue;
		}
		if (!Number.isInteger(port.to) || port.to < port.from || port.to > PORT_MAX){
			portErrors[index] = "The end port must be between the start port and 65535.";
		}
	}

	const validPorts = ports
		.map((port, index) => ({port, index}))
		.filter(({index}) => !portErrors[index])
		.sort((left, right) => portSort(left.port, right.port));
	for (let index = 1; index < validPorts.length; index += 1){
		const previous = validPorts[index - 1];
		const current = validPorts[index];
		if (current.port.from <= previous.port.to){
			portErrors[current.index] = "This port overlaps another port in this group.";
		}
	}

	return {groupError, portErrors};
};

export const isPortGroupValid = (group) => {
	const validation = validatePortGroup(group);
	return !validation.groupError && validation.portErrors.every((error) => !error);
};

export const validatePolicyGroups = (groups = []) => {
	const policyGroups = Array.isArray(groups) ? groups : [];
	const validations = policyGroups.map((group) => validatePortGroup(group));
	const groupIndexes = new Map();

	for (const [index, group] of policyGroups.entries()){
		const normalized = normalizePortGroup(group);
		if (!normalized.destination) continue;
		const key = portGroupKey(normalized.destination, normalized.protocol);
		if (groupIndexes.has(key)){
			validations[index].groupError = "Duplicate destination and protocol groups are not allowed.";
		}else{
			groupIndexes.set(key, index);
		}
	}

	return validations;
};

export const isPolicyGroupsValid = (groups) => {
	return validatePolicyGroups(groups).every((validation) => {
		return !validation.groupError && validation.portErrors.every((error) => !error);
	});
};

export const portLabel = (port) => {
	const normalized = normalizePort(port);
	return normalized.from === normalized.to ? String(normalized.from) : `${normalized.from}-${normalized.to}`;
};
