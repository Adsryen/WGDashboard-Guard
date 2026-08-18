import assert from "node:assert/strict";
import test from "node:test";

import {
	emptyPortGroup,
	flattenGroups,
	groupRules,
	isPolicyGroupsValid,
	isPortGroupValid,
	validatePolicyGroups,
	validatePortGroup
} from "./portGroups.js";

test("groups legacy flat rules by destination and protocol with sorted ports", () => {
	const groups = groupRules([
		{destination: "192.168.0.175/32", protocol: "tcp", ports: {from: 9001, to: 9001}},
		{destination: "192.168.0.175/32", protocol: "tcp", ports: {from: 3000, to: 3000}},
		{destination: "192.168.0.175/32", protocol: "udp", ports: {from: 53, to: 53}},
		{destination: "192.168.0.175/32", protocol: "tcp", ports: {from: 9000, to: 9000}}
	]);

	assert.equal(groups.length, 2);
	assert.deepEqual(groups[0].ports.map(({from, to}) => ({from, to})), [
		{from: 3000, to: 3000},
		{from: 9000, to: 9000},
		{from: 9001, to: 9001}
	]);
	assert.equal(groups[1].protocol, "udp");
});

test("flattens group ports into the existing API payload shape", () => {
	const rules = flattenGroups([{
		destination: "192.168.0.175/32",
		protocol: "tcp",
		allPorts: false,
		ports: [{from: 9000, to: 9001}, {from: 8118, to: null}]
	}]);

	assert.deepEqual(rules, [
		{destination: "192.168.0.175/32", protocol: "tcp", ports: {from: 8118, to: 8118}},
		{destination: "192.168.0.175/32", protocol: "tcp", ports: {from: 9000, to: 9001}}
	]);
});

test("preserves all-port and ICMP compatibility semantics", () => {
	assert.deepEqual(flattenGroups(groupRules([
		{destination: "192.168.0.170/32", protocol: "tcp", ports: null},
		{destination: "192.168.0.171/32", protocol: "icmp", ports: null}
	])), [
		{destination: "192.168.0.170/32", protocol: "tcp", ports: null},
		{destination: "192.168.0.171/32", protocol: "icmp", ports: null}
	]);
});

test("rejects empty, invalid, overlapping, and mixed all-port groups", () => {
	assert.equal(validatePortGroup({...emptyPortGroup(), destination: "192.168.0.170/32", ports: []}).groupError, "Add at least one port.");
	assert.equal(validatePortGroup({destination: "192.168.0.170/32", protocol: "tcp", allPorts: false, ports: [{from: 0, to: 0}]}).portErrors[0], "Enter a port from 1 to 65535.");
	assert.equal(validatePortGroup({destination: "192.168.0.170/32", protocol: "tcp", allPorts: false, ports: [{from: 9000, to: 9002}, {from: 9001, to: 9003}]}).portErrors[1], "This port overlaps another port in this group.");
	assert.equal(validatePortGroup({destination: "192.168.0.170/32", protocol: "tcp", allPorts: false, ports: [{from: 9001, to: 9003}, {from: 9000, to: 9002}]}).portErrors[0], "This port overlaps another port in this group.");
	assert.equal(validatePortGroup({destination: "192.168.0.170/32", protocol: "tcp", allPorts: true, ports: [{from: 443, to: 443}]}).groupError, "All ports cannot be combined with specific ports.");
	assert.equal(isPortGroupValid({destination: "192.168.0.170/32", protocol: "icmp", allPorts: false, ports: []}), true);
});

test("rejects duplicate destination and protocol groups at the policy level", () => {
	const groups = [
		{destination: "192.168.0.170/32", protocol: "tcp", allPorts: false, ports: [{from: 443, to: 443}]},
		{destination: "192.168.0.170/32", protocol: "udp", allPorts: false, ports: [{from: 53, to: 53}]},
		{destination: " 192.168.0.170/32 ", protocol: "TCP", allPorts: false, ports: [{from: 8443, to: 8443}]}
	];
	const validations = validatePolicyGroups(groups);

	assert.equal(validations[0].groupError, "");
	assert.equal(validations[1].groupError, "");
	assert.equal(validations[2].groupError, "Duplicate destination and protocol groups are not allowed.");
	assert.equal(isPolicyGroupsValid(groups), false);
});
