<script>
import {fetchGet, fetchPost} from "@/utilities/fetch.js";
import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import LocaleText from "@/components/text/localeText.vue";
import {GetLocale} from "@/utilities/locale.js";

const emptyPolicy = () => ({managed: true, rules: []});

export default {
	name: "networkPolicyModal",
	components: {LocaleText},
	props: {
		selectedPeer: Object,
		configurationName: {type: String, default: ""}
	},
	emits: ["close"],
	data(){
		return {
			store: DashboardConfigurationStore(),
			policy: emptyPolicy(),
			tunnelAddress: "",
			capabilities: null,
			revisions: [],
			previewRuleset: "",
			previewHash: "",
			previewRequired: true,
			loading: true,
			applying: false,
			error: ""
		}
	},
	computed: {
		tunnelAddresses(){
			return String(this.selectedPeer?.allowed_ip || "")
				.split(",")
				.map(value => value.trim())
				.filter(value => /\/(32|128)$/.test(value))
				.map(value => value.replace(/\/(32|128)$/, ""))
		},
		canApply(){
			return this.capabilities?.capabilities?.supported === true && !this.previewRequired && !this.applying
		}
	},
	watch: {
		policy: {
			deep: true,
			handler(){
				this.previewRequired = true
			}
		},
		tunnelAddress(){
			this.previewRequired = true
			if (!this.loading){
				this.loadPolicy()
			}
		}
	},
	async mounted(){
		this.tunnelAddress = this.tunnelAddresses[0] || "";
		await Promise.all([this.loadCapabilities(), this.loadPolicy()]);
	},
	methods: {
		GetLocale,
		getConfigurationName(){
			return this.configurationName || this.$route.params.id
		},
		basePayload(){
			return {
				configuration_name: this.getConfigurationName(),
				peer_public_key: this.selectedPeer.id,
				tunnel_address: this.tunnelAddress,
				managed: this.policy.managed,
				rules: this.policy.rules
			}
		},
		async loadCapabilities(){
			await fetchGet("/api/networkPolicy/capabilities", {}, (res) => {
				if (res.status){
					this.capabilities = res.data;
				}else{
					this.error = res.message;
				}
			});
		},
		async loadPolicy(){
			if (!this.tunnelAddress){
				this.error = GetLocale("This Peer needs a single-host Allowed IP before a forwarding policy can be managed.");
				this.loading = false;
				return;
			}
			await fetchPost("/api/networkPolicy/get", this.basePayload(), (res) => {
				if (res.status){
					this.policy = res.data.policy || emptyPolicy();
					this.revisions = res.data.revisions || [];
					this.previewRequired = true;
					this.previewRuleset = "";
				}else{
					this.error = res.message;
				}
				this.loading = false;
			});
		},
		addRule(){
			this.policy.rules.push({destination: "", protocol: "tcp", ports: {from: null, to: null}});
		},
		onManagedChange(){
			if (!this.policy.managed){
				this.policy.rules = [];
			}
		},
		removeRule(index){
			this.policy.rules.splice(index, 1);
		},
		setAllPorts(rule, enabled){
			rule.ports = enabled ? null : {from: null, to: null};
		},
		async preview(){
			this.error = "";
			if (!this.tunnelAddress){
				this.error = GetLocale("Select a single-host tunnel address first.");
				return;
			}
			await fetchPost("/api/networkPolicy/dryRun", this.basePayload(), (res) => {
				if (res.status){
					this.previewRuleset = res.data.ruleset;
					this.previewHash = res.data.hash;
					this.previewRequired = false;
				}else{
					this.error = res.message;
				}
			});
		},
		async apply(){
			if (this.previewRequired){
				this.error = GetLocale("Preview the generated rules before applying this policy.");
				return;
			}
			this.applying = true;
			this.error = "";
			await fetchPost("/api/networkPolicy/apply", this.basePayload(), (res) => {
				if (res.status){
					this.store.newMessage("WGDashboard", GetLocale("Network policy applied"), "success");
					this.previewRequired = true;
					this.previewRuleset = "";
					this.loadPolicy();
				}else{
					this.error = res.message;
				}
				this.applying = false;
			});
		},
		async deactivate(){
			this.applying = true;
			await fetchPost("/api/networkPolicy/deactivate", this.basePayload(), (res) => {
				if (res.status){
					this.store.newMessage("WGDashboard", GetLocale("Network policy disabled"), "success");
					this.policy = emptyPolicy();
					this.previewRuleset = "";
					this.loadPolicy();
				}else{
					this.error = res.message;
				}
				this.applying = false;
			});
		},
		async rollback(revisionId){
			this.applying = true;
			await fetchPost("/api/networkPolicy/rollback", {revision_id: revisionId}, (res) => {
				if (res.status){
					this.store.newMessage("WGDashboard", GetLocale("Network policy rolled back"), "success");
					this.loadPolicy();
				}else{
					this.error = res.message;
				}
				this.applying = false;
			});
		}
	}
}
</script>

<template>
	<div class="peerSettingContainer w-100 h-100 position-absolute top-0 start-0 overflow-y-scroll">
		<div class="dashboardModal bg-body shadow mx-auto my-4 p-4">
			<div class="d-flex align-items-start gap-3 mb-4">
				<div>
					<h5 class="mb-1"><i class="bi bi-shield-lock me-2"></i><LocaleText t="Network Policy"></LocaleText></h5>
					<div class="small text-muted">{{ selectedPeer.name || selectedPeer.id }}</div>
				</div>
				<button type="button" class="btn-close ms-auto" :title="GetLocale('Close')" @click="$emit('close')"></button>
			</div>

			<div v-if="error" class="alert alert-danger py-2 small">{{ error }}</div>
			<div v-if="capabilities && !capabilities.capabilities?.supported" class="alert alert-warning py-2 small">
				{{ capabilities.capabilities?.message }}
			</div>

			<div class="mb-3">
				<label class="form-label small fw-bold"><LocaleText t="Peer tunnel address"></LocaleText></label>
				<select class="form-select" v-model="tunnelAddress" :disabled="tunnelAddresses.length < 2">
					<option v-for="address in tunnelAddresses" :key="address" :value="address">{{ address }}</option>
				</select>
				<div class="form-text"><LocaleText t="Only a single-host Allowed IP can be bound to a forwarding policy."></LocaleText></div>
			</div>

			<div class="form-check form-switch mb-3">
				<input class="form-check-input" id="network-policy-managed" type="checkbox" v-model="policy.managed" @change="onManagedChange">
				<label class="form-check-label" for="network-policy-managed"><LocaleText t="Manage and default-deny forwarded traffic for this Peer"></LocaleText></label>
			</div>

			<div v-if="policy.managed" class="border-top pt-3">
				<div class="d-flex align-items-center mb-2">
					<h6 class="mb-0"><LocaleText t="Allowed destinations"></LocaleText></h6>
					<button type="button" class="btn btn-sm btn-outline-primary ms-auto" :title="GetLocale('Add rule')" @click="addRule"><i class="bi bi-plus-lg"></i></button>
				</div>
				<div v-for="(rule, index) in policy.rules" :key="index" class="rule-row border-bottom py-3">
					<div class="row g-2 align-items-end">
						<div class="col-12 col-md-5">
							<label class="form-label small"><LocaleText t="Destination IP or CIDR"></LocaleText></label>
							<input class="form-control" v-model.trim="rule.destination" placeholder="192.168.10.117/32">
						</div>
						<div class="col-6 col-md-2">
							<label class="form-label small"><LocaleText t="Protocol"></LocaleText></label>
							<select class="form-select" v-model="rule.protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
						</div>
						<div class="col-5 col-md-3">
							<label class="form-label small"><LocaleText t="Ports"></LocaleText></label>
							<div v-if="rule.ports === null" class="form-control text-muted"><LocaleText t="All ports"></LocaleText></div>
							<div v-else class="d-flex gap-1"><input class="form-control" type="number" min="1" max="65535" v-model.number="rule.ports.from" :placeholder="GetLocale('From')"><input class="form-control" type="number" min="1" max="65535" v-model.number="rule.ports.to" :placeholder="GetLocale('To')"></div>
						</div>
						<div class="col-1 col-md-2 d-flex justify-content-end gap-1">
							<button type="button" class="btn btn-sm btn-outline-secondary" :title="GetLocale(rule.ports === null ? 'Use port range' : 'Allow all ports')" @click="setAllPorts(rule, rule.ports !== null)"><i :class="rule.ports === null ? 'bi bi-list-ol' : 'bi bi-infinity'"></i></button>
							<button type="button" class="btn btn-sm btn-outline-danger" :title="GetLocale('Remove rule')" @click="removeRule(index)"><i class="bi bi-trash"></i></button>
						</div>
					</div>
				</div>
				<div v-if="policy.rules.length === 0" class="small text-warning py-2"><LocaleText t="No destination is allowed. Applying this policy denies all forwarded traffic for this Peer."></LocaleText></div>
			</div>

			<div class="d-flex gap-2 border-top mt-4 pt-3">
				<button type="button" class="btn btn-outline-primary" :disabled="loading || applying" @click="preview"><i class="bi bi-eye me-1"></i><LocaleText t="Preview"></LocaleText></button>
				<button type="button" class="btn btn-primary" :disabled="!canApply" @click="apply"><i class="bi bi-shield-check me-1"></i><LocaleText t="Apply"></LocaleText></button>
				<button type="button" class="btn btn-outline-danger ms-auto" :disabled="loading || applying" @click="deactivate"><i class="bi bi-shield-x me-1"></i><LocaleText t="Disable"></LocaleText></button>
			</div>

			<div v-if="previewRuleset" class="mt-3">
				<div class="small fw-bold mb-1"><LocaleText t="Generated nftables rules"></LocaleText> <code>{{ previewHash }}</code></div>
				<pre class="ruleset-preview mb-0">{{ previewRuleset }}</pre>
			</div>

			<div v-if="revisions.length" class="mt-4 border-top pt-3">
				<h6><LocaleText t="Policy history"></LocaleText></h6>
				<div v-for="revision in revisions" :key="revision.revision_id" class="d-flex gap-2 align-items-center py-2 border-bottom small">
					<span :class="revision.status === 'applied' ? 'text-success' : revision.status === 'failed' ? 'text-danger' : 'text-warning'">{{ GetLocale(revision.status) }}</span>
					<span>v{{ revision.version }} · {{ GetLocale(revision.action) }}</span>
					<code class="text-muted text-truncate">{{ revision.hash }}</code>
					<button type="button" class="btn btn-sm btn-outline-secondary ms-auto" :title="GetLocale('Restore this revision')" :disabled="applying" @click="rollback(revision.revision_id)"><i class="bi bi-arrow-counterclockwise"></i></button>
				</div>
			</div>
		</div>
	</div>
</template>

<style scoped>
.dashboardModal { max-width: 980px; }
.ruleset-preview { max-height: 260px; overflow: auto; padding: 0.75rem; border: 1px solid var(--bs-border-color); background: var(--bs-tertiary-bg); font-size: 0.75rem; white-space: pre-wrap; }
.rule-row:last-child { border-bottom: 0 !important; }
</style>
