<script setup>
import {computed, onMounted, reactive, ref} from "vue";
import {fetchGet, fetchPost} from "@/utilities/fetch.js";
import LocaleText from "@/components/text/localeText.vue";
import {GetLocale} from "@/utilities/locale.js";

const PAGE_SIZE = 25;
const MAX_RANGE_DAYS = 31;

const toLocalDateTimeValue = (date) => {
	const offsetDate = new Date(date.getTime() - (date.getTimezoneOffset() * 60_000));
	return offsetDate.toISOString().slice(0, 16);
};

const defaultEnd = new Date();
const defaultStart = new Date(defaultEnd.getTime() - (24 * 60 * 60 * 1000));
const filters = reactive({
	start_time: toLocalDateTimeValue(defaultStart),
	end_time: toLocalDateTimeValue(defaultEnd),
	configuration_name: "",
	peer_name: "",
	peer_public_key: "",
	tunnel_address: "",
	destination: "",
	protocol: "",
	destination_port: "",
	decision: "",
});

const records = ref([]);
const summary = ref(null);
const pagination = ref({page: 1, page_size: PAGE_SIZE, total: 0, total_capped: false});
const health = ref(null);
const alertStatus = ref(null);
const queryError = ref("");
const healthError = ref("");
const alertError = ref("");
const alertMessage = ref("");
const loadingAudit = ref(false);
const loadingHealth = ref(false);
const loadingAlerts = ref(false);
const savingAlerts = ref(false);
const testingAlerts = ref(false);

const alertConfig = reactive({
	alerts_enabled: false,
	audit_alert_recipient: "",
	denied_threshold: 10,
	scan_threshold: 20,
	cooldown_minutes: 30,
	alert_tested_at: null,
	verified: false,
	smtp_ready: false,
});

const decisionLabels = {
	forward_observed: "Forwarding observed",
	policy_allowed: "Policy allowed",
	policy_denied: "Policy denied",
};

const decisionDescriptions = {
	forward_observed: "Gateway observed a forwarded flow without a policy verdict.",
	policy_allowed: "Gateway policy allowed the forwarded flow.",
	policy_denied: "Gateway policy denied the forwarded flow.",
};
const decisions = Object.keys(decisionLabels);

const pick = (source, ...keys) => {
	if (!source) return undefined;
	for (const key of keys){
		if (source[key] !== undefined && source[key] !== null) return source[key];
	}
	return undefined;
};

const asBoolean = (value) => value === true || value === "true" || value === 1 || value === "1";

const asIsoTime = (value) => {
	if (!value) return "";
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? value : date.toISOString();
};

const queryPayload = (page = pagination.value.page) => {
	const payload = {
		start_time: asIsoTime(filters.start_time),
		end_time: asIsoTime(filters.end_time),
		page,
		page_size: PAGE_SIZE,
	};
	for (const field of ["configuration_name", "peer_name", "peer_public_key", "tunnel_address", "destination", "protocol", "decision"]){
		if (filters[field].trim()) payload[field] = filters[field].trim();
	}
	if (filters.destination_port !== "") payload.destination_port = Number(filters.destination_port);
	return payload;
};

const summaryPayload = (payload) => {
	const {page, page_size, ...summaryFilters} = payload;
	return summaryFilters;
};

const localValidationError = () => {
	if (!filters.start_time || !filters.end_time) return GetLocale("Start and end times are required.");
	const start = new Date(filters.start_time);
	const end = new Date(filters.end_time);
	if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return GetLocale("Enter valid dates and times.");
	if (start > end) return GetLocale("Start time must be before end time.");
	if (end.getTime() - start.getTime() > MAX_RANGE_DAYS * 24 * 60 * 60 * 1000) return GetLocale("Time range cannot exceed 31 days.");
	if (filters.destination_port !== "" && (!Number.isInteger(Number(filters.destination_port)) || Number(filters.destination_port) < 1 || Number(filters.destination_port) > 65535)){
		return GetLocale("Enter a port from 1 to 65535.");
	}
	return "";
};

const loadAudit = async (page = 1) => {
	const validationError = localValidationError();
	if (validationError){
		queryError.value = validationError;
		return;
	}
	loadingAudit.value = true;
	queryError.value = "";
	const payload = queryPayload(page);
	await Promise.all([
		fetchPost("/api/networkAudit/query", payload, (res) => {
			if (res.status){
				records.value = res.data?.records || [];
				pagination.value = {...pagination.value, ...(res.data?.pagination || {}), page};
			}else{
				queryError.value = res.message || GetLocale("Unable to load audit records.");
			}
		}),
		fetchGet("/api/networkAudit/summary", summaryPayload(payload), (res) => {
			if (res.status){
				summary.value = res.data || null;
			}else{
				queryError.value = res.message || GetLocale("Unable to load audit summary.");
			}
		}),
	]);
	loadingAudit.value = false;
};

const normalizeAlertConfig = (data) => ({
	alerts_enabled: asBoolean(pick(data, "alerts_enabled", "enabled")),
	audit_alert_recipient: pick(data, "audit_alert_recipient", "recipient") || "",
	denied_threshold: Number(pick(data, "denied_threshold") || 10),
	scan_threshold: Number(pick(data, "scan_threshold") || 20),
	cooldown_minutes: Number(pick(data, "cooldown_minutes") || 30),
	alert_tested_at: pick(data?.test, "tested_at") || pick(data, "alert_tested_at", "tested_at") || null,
	verified: asBoolean(data?.test?.ready_to_enable),
	smtp_ready: asBoolean(pick(data?.test, "smtp_ready") || pick(data, "smtp_ready", "email_ready")),
});

const mergeAlertConfig = (data) => Object.assign(alertConfig, normalizeAlertConfig(data));

const loadHealth = async () => {
	loadingHealth.value = true;
	healthError.value = "";
	await fetchGet("/api/networkAudit/health", {}, (res) => {
		if (res.status){
			health.value = res.data || {};
		}else{
			health.value = res.data || null;
			healthError.value = res.message || GetLocale("Collector health information is unavailable.");
		}
		loadingHealth.value = false;
	});
};

const loadAlerts = async () => {
	loadingAlerts.value = true;
	alertError.value = "";
	await Promise.all([
		fetchGet("/api/networkAudit/alerts/config", {}, (res) => {
			if (res.status){
				mergeAlertConfig(res.data || {});
			}else{
				alertError.value = res.message || GetLocale("Unable to load alert settings.");
			}
		}),
		fetchGet("/api/networkAudit/alerts/status", {}, (res) => {
			if (res.status){
				alertStatus.value = res.data || {};
			}else{
				alertError.value = res.message || GetLocale("Unable to load alert status.");
			}
		}),
	]);
	loadingAlerts.value = false;
};

const refreshAll = async () => {
	await Promise.all([loadAudit(1), loadHealth(), loadAlerts()]);
};

const saveAlerts = async () => {
	alertError.value = "";
	alertMessage.value = "";
	if (!alertConfig.audit_alert_recipient.trim()){
		alertError.value = GetLocale("Enter one alert recipient email address.");
		return;
	}
	if (alertConfig.alerts_enabled && !alertConfig.verified){
		alertError.value = GetLocale("Send and complete a test email before enabling alerts.");
		return;
	}
	savingAlerts.value = true;
	await fetchPost("/api/networkAudit/alerts/config", {
		alerts_enabled: alertConfig.alerts_enabled,
		audit_alert_recipient: alertConfig.audit_alert_recipient.trim(),
		denied_threshold: Number(alertConfig.denied_threshold),
		scan_threshold: Number(alertConfig.scan_threshold),
		cooldown_minutes: Number(alertConfig.cooldown_minutes),
	}, async (res) => {
		if (res.status){
			mergeAlertConfig(res.data || {});
			alertMessage.value = GetLocale("Alert settings saved.");
			await loadAlerts();
		}else{
			alertError.value = res.message || GetLocale("Unable to save alert settings.");
		}
		savingAlerts.value = false;
	});
};

const sendAlertTest = async () => {
	alertError.value = "";
	alertMessage.value = "";
	if (!alertConfig.audit_alert_recipient.trim()){
		alertError.value = GetLocale("Enter one alert recipient email address.");
		return;
	}
	testingAlerts.value = true;
	await fetchPost("/api/networkAudit/alerts/test", {
		audit_alert_recipient: alertConfig.audit_alert_recipient.trim(),
	}, async (res) => {
		if (res.status){
			mergeAlertConfig(res.data || {});
			alertMessage.value = GetLocale("Test email sent. This recipient can now enable alerts.");
			await loadAlerts();
		}else{
			alertError.value = res.message || GetLocale("Test email could not be sent. Check SMTP settings and the recipient address.");
		}
		testingAlerts.value = false;
	});
};

const totalPages = computed(() => Math.max(1, Math.ceil((pagination.value.total || 0) / PAGE_SIZE)));
const canGoPrevious = computed(() => pagination.value.page > 1 && !loadingAudit.value);
const canGoNext = computed(() => pagination.value.page < totalPages.value && !loadingAudit.value);
const healthStatus = computed(() => pick(health.value, "state", "status", "health_status") || "unknown");
const healthClass = computed(() => ({healthy: "text-bg-success", degraded: "text-bg-warning", failed: "text-bg-danger", stale: "text-bg-warning", missing: "text-bg-danger", error: "text-bg-danger"}[healthStatus.value] || "text-bg-secondary"));
const healthLabel = computed(() => GetLocale(healthStatus.value));
const alertReady = computed(() => alertConfig.smtp_ready && Boolean(alertConfig.audit_alert_recipient) && alertConfig.verified);
const decisionLabel = (decision) => GetLocale(decisionLabels[decision] || decision || "Unknown");
const decisionClass = (decision) => ({policy_allowed: "text-bg-success", policy_denied: "text-bg-danger", forward_observed: "text-bg-secondary"}[decision] || "text-bg-secondary");
const formatTime = (value) => {
	if (!value || value === "-") return "-";
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
};
const formatBytes = (value) => {
	const bytes = Number(value || 0);
	if (!Number.isFinite(bytes)) return "-";
	const units = ["B", "KB", "MB", "GB", "TB"];
	let amount = bytes;
	let unit = 0;
	while (amount >= 1024 && unit < units.length - 1){ amount /= 1024; unit += 1; }
	return `${amount.toFixed(unit ? 1 : 0)} ${units[unit]}`;
};
const portLabel = (record) => record.destination_port === null || record.destination_port === undefined ? GetLocale("No ports for ICMP") : record.destination_port;
const healthValue = (...keys) => pick(health.value?.snapshot, ...keys) ?? pick(health.value, ...keys) ?? "-";
const alertValue = (...keys) => pick(alertStatus.value?.latest_delivery, ...keys)
	?? pick(alertStatus.value?.latest_run, ...keys)
	?? pick(alertStatus.value, ...keys)
	?? "-";

onMounted(refreshAll);
</script>

<template>
	<div class="container-fluid network-audit pb-4 text-body">
		<div class="d-flex flex-column flex-xl-row align-items-xl-center gap-3 mb-4">
			<div>
				<h2 class="mb-1"><i class="bi bi-activity me-2"></i><LocaleText t="Network access audit" /></h2>
				<p class="text-muted mb-0"><LocaleText t="Review WireGuard forwarding metadata and audit alert readiness." /></p>
			</div>
			<button class="btn btn-outline-secondary ms-xl-auto" type="button" :disabled="loadingAudit || loadingHealth || loadingAlerts" :title="GetLocale('Refresh')" @click="refreshAll">
				<i :class="['bi bi-arrow-clockwise', {spin: loadingAudit || loadingHealth || loadingAlerts}]"></i>
			</button>
		</div>

		<div class="alert alert-info d-flex gap-2 align-items-start" role="note">
			<i class="bi bi-info-circle-fill mt-1"></i>
			<span><LocaleText t="Audit decisions describe gateway observation or policy verdicts. They do not confirm that a remote application service succeeded." /></span>
		</div>

		<div class="row g-3 mb-3">
			<div class="col-12 col-xl-8">
				<div class="card h-100 shadow-sm">
					<div class="card-header d-flex align-items-center gap-2">
						<i class="bi bi-bar-chart-fill"></i><strong><LocaleText t="Last 24 hours summary" /></strong>
					</div>
					<div class="card-body">
						<div class="row g-2" v-if="summary">
							<div class="col-6 col-md-3"><div class="summary-stat"><small><LocaleText t="Activity windows" /></small><strong>{{ summary.window_count || 0 }}</strong></div></div>
							<div class="col-6 col-md-3"><div class="summary-stat"><small><LocaleText t="Connections" /></small><strong>{{ summary.connection_count || 0 }}</strong></div></div>
							<div class="col-6 col-md-3"><div class="summary-stat"><small><LocaleText t="From Peer" /></small><strong>{{ formatBytes(summary.bytes_from_peer) }}</strong></div></div>
							<div class="col-6 col-md-3"><div class="summary-stat"><small><LocaleText t="To Peer" /></small><strong>{{ formatBytes(summary.bytes_to_peer) }}</strong></div></div>
						</div>
						<p class="text-muted small mb-0 mt-3" v-if="summary"><LocaleText t="Latest activity window:" /> {{ formatTime(summary.latest_window_started_at) }}</p>
						<div class="text-muted" v-else><LocaleText t="No summary is available for the selected range." /></div>
					</div>
				</div>
			</div>
			<div class="col-12 col-xl-4">
				<div class="card h-100 shadow-sm">
					<div class="card-header d-flex align-items-center gap-2"><i class="bi bi-heart-pulse-fill"></i><strong><LocaleText t="Collector health" /></strong></div>
					<div class="card-body" v-if="health">
						<div class="d-flex align-items-center gap-2 mb-3"><span class="badge" :class="healthClass">{{ healthLabel }}</span><small class="text-muted"><LocaleText t="Read-only collector status" /></small></div>
						<dl class="row small mb-0 health-list">
							<dt class="col-6"><LocaleText t="Last heartbeat" /></dt><dd class="col-6">{{ formatTime(healthValue('observed_at', 'last_heartbeat_at', 'updated_at')) }}</dd>
							<dt class="col-6"><LocaleText t="Last persisted" /></dt><dd class="col-6">{{ formatTime(healthValue('last_persisted_at', 'last_write_at')) }}</dd>
							<dt class="col-6"><LocaleText t="Spool usage" /></dt><dd class="col-6">{{ healthValue('spool_records') }} <LocaleText t="records" /> / {{ formatBytes(healthValue('spool_bytes')) }}</dd>
							<dt class="col-6"><LocaleText t="Dropped records" /></dt><dd class="col-6">{{ healthValue('dropped_records', 'spool_dropped_records') }}</dd>
							<dt class="col-6"><LocaleText t="Write failures" /></dt><dd class="col-6">{{ healthValue('write_failures') }}</dd>
							<dt class="col-6"><LocaleText t="Configuration sync" /></dt><dd class="col-6">{{ healthValue('config_sync_status') }}</dd>
						</dl>
						<p class="alert alert-warning small mb-0 mt-3" v-if="healthValue('last_error') !== '-'"><strong><LocaleText t="Collector action needed:" /></strong> {{ healthValue('last_error') }}</p>
					</div>
					<div class="card-body" v-else>
						<p class="alert alert-warning mb-0"><LocaleText t="Collector health information is unavailable. Verify that the collector service is running and can write its health snapshot." /></p>
					</div>
				</div>
			</div>
		</div>

		<div class="card shadow-sm mb-3">
			<div class="card-header d-flex align-items-center gap-2"><i class="bi bi-funnel-fill"></i><strong><LocaleText t="Audit filters" /></strong></div>
			<form class="card-body" @submit.prevent="loadAudit(1)">
				<div class="row g-2">
					<div class="col-12 col-md-6 col-xl-3"><label class="form-label small" for="auditStart"><LocaleText t="Start time" /></label><input id="auditStart" v-model="filters.start_time" class="form-control" type="datetime-local" required></div>
					<div class="col-12 col-md-6 col-xl-3"><label class="form-label small" for="auditEnd"><LocaleText t="End time" /></label><input id="auditEnd" v-model="filters.end_time" class="form-control" type="datetime-local" required></div>
					<div class="col-12 col-md-6 col-xl-3"><label class="form-label small" for="auditConfiguration"><LocaleText t="Configuration" /></label><input id="auditConfiguration" v-model="filters.configuration_name" class="form-control" type="text"></div>
					<div class="col-12 col-md-6 col-xl-3"><label class="form-label small" for="auditPeerName"><LocaleText t="Peer name" /></label><input id="auditPeerName" v-model="filters.peer_name" class="form-control" type="text"></div>
					<div class="col-12 col-md-6 col-xl-3"><label class="form-label small" for="auditPeerKey"><LocaleText t="Peer public key" /></label><input id="auditPeerKey" v-model="filters.peer_public_key" class="form-control" type="text"></div>
					<div class="col-12 col-md-6 col-xl-3"><label class="form-label small" for="auditTunnel"><LocaleText t="Tunnel address" /></label><input id="auditTunnel" v-model="filters.tunnel_address" class="form-control" type="text"></div>
					<div class="col-12 col-md-6 col-xl-3"><label class="form-label small" for="auditDestination"><LocaleText t="Destination IP or CIDR" /></label><input id="auditDestination" v-model="filters.destination" class="form-control" type="text"></div>
					<div class="col-6 col-md-3 col-xl-1"><label class="form-label small" for="auditProtocol"><LocaleText t="Protocol" /></label><select id="auditProtocol" v-model="filters.protocol" class="form-select"><option value=""><LocaleText t="All" /></option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></div>
					<div class="col-6 col-md-3 col-xl-1"><label class="form-label small" for="auditPort"><LocaleText t="Port" /></label><input id="auditPort" v-model="filters.destination_port" class="form-control" type="number" min="1" max="65535"></div>
					<div class="col-12 col-md-6 col-xl-2"><label class="form-label small" for="auditDecision"><LocaleText t="Decision" /></label><select id="auditDecision" v-model="filters.decision" class="form-select"><option value=""><LocaleText t="All" /></option><option value="forward_observed"><LocaleText t="Forwarding observed" /></option><option value="policy_allowed"><LocaleText t="Policy allowed" /></option><option value="policy_denied"><LocaleText t="Policy denied" /></option></select></div>
				</div>
				<div class="d-flex flex-wrap gap-2 align-items-center mt-3"><button class="btn btn-primary" :disabled="loadingAudit" type="submit"><span class="spinner-border spinner-border-sm me-2" v-if="loadingAudit"></span><i class="bi bi-search me-2" v-else></i><LocaleText t="Search audit records" /></button><small class="text-muted"><LocaleText t="Times are converted to UTC for the audit query. The maximum range is 31 days." /></small></div>
				<p class="alert alert-danger small mb-0 mt-3" v-if="queryError"><strong><LocaleText t="Audit query failed:" /></strong> {{ queryError }}</p>
			</form>
		</div>

		<div class="card shadow-sm mb-3">
			<div class="card-header d-flex flex-column flex-md-row align-items-md-center gap-2"><div><i class="bi bi-table me-2"></i><strong><LocaleText t="Activity windows" /></strong></div><small class="text-muted ms-md-auto"><LocaleText t="Results are fixed UTC five-minute windows." /> {{ pagination.total }} <LocaleText t="results" /></small></div>
			<div class="table-responsive">
				<table class="table table-hover align-middle mb-0">
					<thead><tr><th><LocaleText t="Window" /></th><th><LocaleText t="Peer" /></th><th><LocaleText t="Destination" /></th><th><LocaleText t="Protocol" /></th><th><LocaleText t="Decision" /></th><th><LocaleText t="First seen" /></th><th><LocaleText t="Last seen" /></th><th><LocaleText t="Connections" /></th><th><LocaleText t="From Peer" /></th><th><LocaleText t="To Peer" /></th></tr></thead>
					<tbody>
						<tr v-for="record in records" :key="[record.window_started_at, record.peer_public_key, record.destination_address, record.protocol, record.destination_port, record.decision].join(':')">
							<td class="text-nowrap">{{ formatTime(record.window_started_at) }}</td>
							<td><strong>{{ record.peer_name_snapshot || '-' }}</strong><small class="d-block text-muted text-break">{{ record.peer_public_key }}</small><small class="d-block text-muted">{{ record.configuration_name }} · {{ record.tunnel_address }}</small></td>
							<td class="text-break">{{ record.destination_address }}</td><td>{{ String(record.protocol || '').toUpperCase() }}<span class="d-block text-muted small">{{ portLabel(record) }}</span></td><td><span class="badge" :class="decisionClass(record.decision)">{{ decisionLabel(record.decision) }}</span></td><td class="text-nowrap">{{ formatTime(record.first_seen_at) }}</td><td class="text-nowrap">{{ formatTime(record.last_seen_at) }}</td><td>{{ record.connection_count }}</td><td>{{ formatBytes(record.bytes_from_peer) }}</td><td>{{ formatBytes(record.bytes_to_peer) }}</td>
						</tr>
						<tr v-if="!loadingAudit && records.length === 0"><td colspan="10" class="text-center text-muted py-4"><LocaleText t="No audit activity matches the selected filters." /></td></tr>
						<tr v-if="loadingAudit"><td colspan="10" class="text-center py-4"><span class="spinner-border spinner-border-sm me-2"></span><LocaleText t="Loading audit records..." /></td></tr>
					</tbody>
				</table>
			</div>
			<div class="card-footer d-flex align-items-center gap-2"><button class="btn btn-outline-secondary btn-sm" :disabled="!canGoPrevious" @click="loadAudit(pagination.page - 1)"><LocaleText t="Previous" /></button><span class="small text-muted"><LocaleText t="Page" /> {{ pagination.page }} <LocaleText t="of" /> {{ totalPages }}</span><button class="btn btn-outline-secondary btn-sm" :disabled="!canGoNext" @click="loadAudit(pagination.page + 1)"><LocaleText t="Next" /></button><small class="text-muted ms-auto" v-if="pagination.total_capped"><LocaleText t="Only the first 5,000 matching results are available." /></small></div>
		</div>

		<div class="row g-3 mb-3">
			<div class="col-12 col-xl-5">
				<div class="card h-100 shadow-sm">
					<div class="card-header d-flex align-items-center gap-2"><i class="bi bi-envelope-exclamation-fill"></i><strong><LocaleText t="Audit alert status" /></strong></div>
					<div class="card-body">
						<div class="alert mb-3" :class="alertReady ? 'alert-success' : 'alert-warning'"><strong><LocaleText :t="alertReady ? 'Alert delivery is ready.' : 'Alert delivery needs attention.'" /></strong><span class="d-block mt-1"><LocaleText :t="alertReady ? 'A tested recipient and ready SMTP configuration are available.' : 'Configure SMTP, enter one recipient, send a test email, then enable alerts.'" /></span></div>
						<dl class="row small mb-0 health-list"><dt class="col-6"><LocaleText t="Last evaluation" /></dt><dd class="col-6">{{ formatTime(alertValue('ran_at')) }}</dd><dt class="col-6"><LocaleText t="Last delivery" /></dt><dd class="col-6">{{ formatTime(alertValue('delivered_at')) }}</dd><dt class="col-6"><LocaleText t="Tested at" /></dt><dd class="col-6">{{ formatTime(alertConfig.alert_tested_at) }}</dd><dt class="col-6"><LocaleText t="Alerts enabled" /></dt><dd class="col-6"><LocaleText :t="alertConfig.alerts_enabled ? 'Enabled' : 'Disabled'" /></dd></dl>
						<p class="alert alert-danger small mb-0 mt-3" v-if="alertValue('last_error', 'error') !== '-'"><strong><LocaleText t="Alert delivery action needed:" /></strong> {{ alertValue('last_error', 'error') }}</p>
						<p class="alert alert-warning small mb-0 mt-3" v-if="alertError"><strong><LocaleText t="Alert status could not be loaded:" /></strong> {{ alertError }}</p>
					</div>
				</div>
			</div>
			<div class="col-12 col-xl-7">
				<div class="card h-100 shadow-sm">
					<div class="card-header d-flex align-items-center gap-2"><i class="bi bi-sliders"></i><strong><LocaleText t="Audit alert settings" /></strong></div>
					<form class="card-body" @submit.prevent="saveAlerts">
						<div class="form-check form-switch mb-3"><input id="alertsEnabled" v-model="alertConfig.alerts_enabled" class="form-check-input" type="checkbox" role="switch"><label class="form-check-label" for="alertsEnabled"><LocaleText t="Enable audit email alerts" /></label></div>
						<div class="row g-3">
							<div class="col-12"><label class="form-label" for="alertRecipient"><LocaleText t="Alert recipient" /></label><input id="alertRecipient" v-model="alertConfig.audit_alert_recipient" class="form-control" type="email" :placeholder="GetLocale('One email address')" required><div class="form-text"><LocaleText t="Use one recipient only. This is separate from the SMTP sender address." /></div></div>
							<div class="col-12 col-md-4"><label class="form-label small" for="deniedThreshold"><LocaleText t="Denied connections threshold" /></label><input id="deniedThreshold" v-model.number="alertConfig.denied_threshold" class="form-control" type="number" min="1" required><div class="form-text"><LocaleText t="Per Peer in five minutes" /></div></div>
							<div class="col-12 col-md-4"><label class="form-label small" for="scanThreshold"><LocaleText t="Scan destinations threshold" /></label><input id="scanThreshold" v-model.number="alertConfig.scan_threshold" class="form-control" type="number" min="1" required><div class="form-text"><LocaleText t="Distinct destination IP and port pairs per Peer" /></div></div>
							<div class="col-12 col-md-4"><label class="form-label small" for="cooldown"><LocaleText t="Cooldown minutes" /></label><input id="cooldown" v-model.number="alertConfig.cooldown_minutes" class="form-control" type="number" min="1" required><div class="form-text"><LocaleText t="For each alert identity" /></div></div>
						</div>
						<p class="small text-muted mt-3 mb-0"><LocaleText t="Default detection: 10 denied connections or 20 distinct destination IP and port pairs for one Peer within five minutes, with a 30-minute cooldown." /></p>
						<div class="d-flex flex-wrap gap-2 mt-3"><button class="btn btn-outline-primary" type="button" :disabled="testingAlerts" @click="sendAlertTest"><span class="spinner-border spinner-border-sm me-2" v-if="testingAlerts"></span><i class="bi bi-send me-2" v-else></i><LocaleText t="Send test email" /></button><button class="btn btn-primary" type="submit" :disabled="savingAlerts"><span class="spinner-border spinner-border-sm me-2" v-if="savingAlerts"></span><i class="bi bi-save me-2" v-else></i><LocaleText t="Save alert settings" /></button></div>
						<p class="alert alert-success small mb-0 mt-3" v-if="alertMessage">{{ alertMessage }}</p><p class="alert alert-danger small mb-0 mt-3" v-if="alertError"><strong><LocaleText t="Alert settings action needed:" /></strong> {{ alertError }}</p>
					</form>
				</div>
			</div>
		</div>

		<div class="card shadow-sm"><div class="card-header"><i class="bi bi-signpost-split me-2"></i><strong><LocaleText t="Decision meanings" /></strong></div><div class="card-body"><div class="row g-3"><div v-for="decision in decisions" :key="decision" class="col-12 col-md-4"><span class="badge mb-2" :class="decisionClass(decision)">{{ decisionLabel(decision) }}</span><p class="small text-muted mb-0"><LocaleText :t="decisionDescriptions[decision]" /></p></div></div></div></div>
	</div>
</template>

<style scoped>
.summary-stat {
	background: var(--bs-tertiary-bg);
	border-radius: var(--bs-border-radius);
	display: flex;
	flex-direction: column;
	gap: .25rem;
	padding: .75rem;
}

.summary-stat small,
.health-list dt {
	color: var(--bs-secondary-color);
	font-weight: 600;
}

.summary-stat strong {
	font-size: 1.15rem;
}

.health-list dd {
	margin-bottom: .45rem;
	overflow-wrap: anywhere;
}

.spin {
	animation: spin .8s linear infinite;
}

@keyframes spin {
	to { transform: rotate(360deg); }
}
</style>
