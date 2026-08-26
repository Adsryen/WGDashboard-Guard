<script setup>
import {computed, defineAsyncComponent, onMounted, ref} from "vue";
import {fetchGet, getUrl} from "@/utilities/fetch.js";
import LocaleText from "@/components/text/localeText.vue";
import {GetLocale} from "@/utilities/locale.js";
import {createPolicyTarget} from "@/components/networkPolicy/policyTarget.js";
import {groupRules, portLabel} from "@/components/networkPolicy/portGroups.js";
import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";

const NetworkPolicyModal = defineAsyncComponent(() => import("@/components/networkPolicy/networkPolicyModal.vue"));

const loading = ref(true);
const error = ref("");
const syncing = ref(false);
const syncError = ref("");
const syncSuccess = ref(false);
const rows = ref([]);
const runtime = ref({status: "not_applicable"});
const selectedTarget = ref(null);
const policyModalOpen = ref(false);
const statusFilter = ref("all");
const configurationFilter = ref("all");
const search = ref("");

const statusOrder = ["managed", "unmanaged", "disabled", "ineligible", "orphaned"];
const statusKeys = {
	managed: "Managed",
	unmanaged: "Unmanaged",
	disabled: "Disabled",
	ineligible: "Ineligible",
	orphaned: "Orphaned"
};

const runtimeClass = computed(() => ({in_sync: "alert-success", out_of_sync: "alert-danger", unavailable: "alert-warning"}[runtime.value.status]));
const runtimeMessage = computed(() => ({
	in_sync: "nftables rules are in sync",
	out_of_sync: "nftables rules do not match the active policies",
	unavailable: "nftables state could not be verified"
}[runtime.value.status]));

const runtimeSyncHeaders = () => {
	const headers = {"Content-Type": "application/json"};
	const crossServer = DashboardConfigurationStore().getActiveCrossServer();
	if (crossServer){
		headers["wg-dashboard-apikey"] = crossServer.apiKey;
		if (crossServer.headers){
			for (const header of Object.values(crossServer.headers)){
				if (header.key && header.value && !Object.prototype.hasOwnProperty.call(headers, header.key)){
					headers[header.key] = header.value;
				}
			}
		}
	}
	return headers;
};

const loadOverview = async (clearRuntimeFeedback = true) => {
	loading.value = true;
	error.value = "";
	if (clearRuntimeFeedback){
		syncError.value = "";
		syncSuccess.value = false;
	}
	let loaded = false;
	await fetchGet("/api/networkPolicy/overview", {}, (res) => {
		if (res.status){
			rows.value = res.data?.rows || [];
			runtime.value = res.data?.runtime || {status: "not_applicable"};
			loaded = true;
		}else{
			error.value = res.message || GetLocale("Failed");
		}
		loading.value = false;
	});
	loading.value = false;
	return loaded;
};

onMounted(loadOverview);

const configurations = computed(() => [...new Set(rows.value.map(row => row.configuration_name))].sort());
const summary = computed(() => Object.fromEntries(statusOrder.map(status => [
	status,
	rows.value.filter(row => row.policy_status === status).length
])));
const filteredRows = computed(() => {
	const term = search.value.trim().toLowerCase();
	return rows.value.filter(row => {
		const matchesStatus = statusFilter.value === "all" || row.policy_status === statusFilter.value;
		const matchesConfiguration = configurationFilter.value === "all" || row.configuration_name === configurationFilter.value;
		const haystack = [row.configuration_name, row.peer_name, row.tunnel_address, row.allowed_ip, row.peer_public_key]
			.join(" ").toLowerCase();
		return matchesStatus && matchesConfiguration && (!term || haystack.includes(term));
	});
});

const statusLabel = (status) => GetLocale(statusKeys[status] || status);
const statusClass = (status) => ({
	managed: "text-bg-success",
	unmanaged: "text-bg-secondary",
	disabled: "text-bg-warning",
	ineligible: "text-bg-dark",
	orphaned: "text-bg-danger"
}[status] || "text-bg-secondary");
const ruleSummary = (row) => {
	if (!row.rules?.length){
		return row.policy_status === "managed" ? GetLocale("No destination is allowed. Applying this policy denies all forwarded traffic for this Peer.") : "-";
	}
	return groupRules(row.rules).map(group => {
		const ports = group.protocol === "icmp" ? "" : group.allPorts ? "" : `:${group.ports.map(portLabel).join(",")}`;
		return `${group.destination} ${group.protocol.toUpperCase()}${ports}`;
	}).join("; ");
};
const formatDate = (value) => value ? new Date(value.replace(" ", "T") + "Z").toLocaleString() : "-";
const canOpenPolicy = (row) => row.peer_present && row.eligible;
const peerTunnelAddresses = (row) => rows.value
	.filter(candidate => candidate.peer_present
		&& candidate.eligible
		&& candidate.configuration_name === row.configuration_name
		&& candidate.peer_public_key === row.peer_public_key)
	.map(candidate => candidate.tunnel_address)
	.filter(Boolean);
const openPolicy = (row) => {
	if (!canOpenPolicy(row)) return;
	selectedTarget.value = createPolicyTarget({
		peer: row,
		configurationName: row.configuration_name,
		tunnelAddress: row.tunnel_address,
		tunnelAddresses: peerTunnelAddresses(row)
	});
	policyModalOpen.value = true;
};
const closePolicy = async () => {
	policyModalOpen.value = false;
	await loadOverview();
};

const syncRuntime = async () => {
	if (runtime.value.status !== "out_of_sync" || syncing.value) return;
	syncing.value = true;
	syncError.value = "";
	syncSuccess.value = false;
	try {
		const response = await fetch(getUrl("/api/networkPolicy/sync"), {
			method: "POST",
			headers: runtimeSyncHeaders(),
			credentials: "same-origin",
			body: JSON.stringify({})
		});
		let result;
		try {
			result = await response.json();
		}catch (_error){
			result = null;
		}
		if (!response.ok || result?.status !== true || result.data?.status !== "in_sync"){
			throw new Error(result?.message || GetLocale("Unable to synchronize nftables rules"));
		}
		if (!await loadOverview(false)){
			throw new Error(GetLocale("Unable to refresh network policy status"));
		}
		syncSuccess.value = true;
	}catch (requestError){
		syncError.value = requestError instanceof Error
			? requestError.message
			: GetLocale("Unable to synchronize nftables rules");
	}finally {
		syncing.value = false;
	}
};
</script>

<template>
	<div class="container-fluid network-policy-overview pb-4">
		<div class="d-flex flex-column flex-md-row align-items-md-center gap-3 mb-4">
			<div>
				<h2 class="mb-1"><i class="bi bi-shield-lock me-2"></i><LocaleText t="Network policy overview" /></h2>
				<p class="text-muted mb-0"><LocaleText t="Review forwarding access rules for every Peer" /></p>
			</div>
			<button class="btn btn-outline-secondary ms-md-auto" type="button" :disabled="loading || syncing" :title="GetLocale('Refresh')" @click="loadOverview()">
				<i :class="['bi bi-arrow-clockwise', {spin: loading || syncing}]"></i>
			</button>
		</div>

		<div class="row g-2 mb-3">
			<div v-for="status in statusOrder" :key="status" class="col-6 col-md">
				<button class="summary-button w-100 text-start" :class="{active: statusFilter === status}" type="button" @click="statusFilter = statusFilter === status ? 'all' : status">
					<span class="small text-muted"><LocaleText :t="statusKeys[status]" /></span>
					<strong class="d-block fs-4">{{ summary[status] || 0 }}</strong>
				</button>
			</div>
		</div>
		<div v-if="runtimeMessage" class="alert py-2 small d-flex flex-wrap align-items-center gap-2" :class="runtimeClass" role="status" aria-live="polite">
			<i :class="runtime.status === 'in_sync' ? 'bi bi-shield-check' : 'bi bi-shield-exclamation'"></i>
			<span><LocaleText :t="runtimeMessage" /></span>
			<button v-if="runtime.status === 'out_of_sync'" class="btn btn-sm btn-danger ms-auto" type="button" :disabled="loading || syncing" @click="syncRuntime">
				<span v-if="syncing" class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>
				<i v-else class="bi bi-arrow-repeat me-1"></i>
				<LocaleText :t="syncing ? 'Syncing nftables rules...' : 'Sync nftables rules'" />
			</button>
		</div>
		<div v-if="syncSuccess" class="alert alert-success py-2 small d-flex align-items-center gap-2" role="status" aria-live="polite">
			<i class="bi bi-check-circle"></i>
			<span><LocaleText t="nftables rules synchronized successfully" /></span>
		</div>
		<div v-if="syncError" class="alert alert-danger py-2 small d-flex align-items-center gap-2" role="alert">
			<i class="bi bi-exclamation-triangle"></i>
			<span><LocaleText t="Runtime synchronization failed" />: {{ syncError }}</span>
		</div>

		<div class="toolbar border-top border-bottom py-3 mb-3 d-flex flex-column flex-lg-row gap-2">
			<div class="input-group input-group-sm search-control">
				<span class="input-group-text"><i class="bi bi-search"></i></span>
				<input v-model="search" class="form-control" type="search" :placeholder="GetLocale('Search Peers...')">
			</div>
			<select v-model="configurationFilter" class="form-select form-select-sm">
				<option value="all"><LocaleText t="All configurations" /></option>
				<option v-for="configuration in configurations" :key="configuration" :value="configuration">{{ configuration }}</option>
			</select>
			<select v-model="statusFilter" class="form-select form-select-sm">
				<option value="all"><LocaleText t="All policy states" /></option>
				<option v-for="status in statusOrder" :key="status" :value="status"><LocaleText :t="statusKeys[status]" /></option>
			</select>
		</div>

		<div v-if="error" class="alert alert-danger">{{ error }}</div>
		<div v-else class="table-responsive border rounded-3">
			<table class="table table-hover align-middle mb-0">
				<thead class="table-light">
					<tr>
						<th><LocaleText t="Peer" /></th>
						<th><LocaleText t="Configuration" /></th>
						<th><LocaleText t="Peer tunnel address" /></th>
						<th><LocaleText t="Policy status" /></th>
						<th><LocaleText t="Allowed destinations" /></th>
						<th><LocaleText t="Last applied" /></th>
						<th class="text-end"><LocaleText t="Actions" /></th>
					</tr>
				</thead>
				<tbody v-if="loading">
					<tr><td colspan="7" class="text-center py-5"><span class="spinner-border spinner-border-sm me-2"></span><LocaleText t="Loading..." /></td></tr>
				</tbody>
				<tbody v-else-if="filteredRows.length">
					<tr v-for="row in filteredRows" :key="`${row.configuration_name}-${row.peer_public_key}-${row.tunnel_address}`">
						<td>
							<strong>{{ row.peer_name || row.peer_public_key.slice(0, 12) }}</strong>
							<div class="small text-muted font-monospace">{{ row.peer_public_key.slice(0, 18) }}...</div>
						</td>
						<td><samp>{{ row.configuration_name }}</samp></td>
						<td>
							<code v-if="row.tunnel_address">{{ row.tunnel_address }}</code>
							<span v-else class="small text-muted"><LocaleText t="Single-host tunnel address is required" /></span>
						</td>
						<td>
							<span class="badge" :class="statusClass(row.policy_status)">{{ statusLabel(row.policy_status) }}</span>
							<div v-if="row.policy_status === 'orphaned'" class="small text-danger mt-1"><LocaleText t="No current Peer binding exists for this policy" /></div>
							<div v-else-if="row.last_apply_status === 'failed'" class="small text-danger mt-1"><LocaleText t="Failed" /></div>
						</td>
						<td class="rule-summary">
							<span :title="ruleSummary(row)">{{ ruleSummary(row) }}</span>
							<div v-if="row.rule_count" class="small text-muted mt-1">{{ row.rule_count }} <LocaleText t="Rules" /></div>
						</td>
						<td class="small text-muted">{{ formatDate(row.last_apply_at || row.updated_at) }}</td>
						<td class="text-end">
							<button class="btn btn-sm btn-primary" type="button" :disabled="!canOpenPolicy(row)" :title="canOpenPolicy(row) ? GetLocale('Configure policy') : GetLocale('Single-host tunnel address is required')" @click="openPolicy(row)">
								<i class="bi bi-shield-lock me-1"></i><LocaleText t="Configure policy" />
							</button>
						</td>
					</tr>
				</tbody>
				<tbody v-else>
					<tr><td colspan="7" class="text-center text-muted py-5"><LocaleText t="No Peer matches the current filters" /></td></tr>
				</tbody>
			</table>
		</div>
	</div>

	<NetworkPolicyModal v-if="policyModalOpen && selectedTarget" :target="selectedTarget" @changed="loadOverview" @close="closePolicy" />
</template>

<style scoped>
.network-policy-overview { max-width: 1600px; }
.summary-button { border: 1px solid var(--bs-border-color); border-radius: 6px; background: var(--bs-body-bg); padding: 0.7rem 0.8rem; }
.summary-button:hover, .summary-button.active { border-color: var(--bs-primary); background: var(--bs-primary-bg-subtle); }
.toolbar select { max-width: 220px; }
.search-control { max-width: 420px; }
.rule-summary { min-width: 260px; max-width: 460px; word-break: break-word; }
.spin { display: inline-block; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (max-width: 992px) { .toolbar select, .search-control { max-width: none; width: 100%; } }
</style>
