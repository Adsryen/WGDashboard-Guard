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
		target: {type: Object, required: true}
	},
	emits: ["close", "changed"],
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
			hasPersistedPolicy: false,
			persistedSignature: "",
			disableConfirmation: false,
			loading: true,
			applying: false,
			error: ""
		}
	},
	computed: {
		tunnelAddresses(){
			return String(this.target.peer?.allowed_ip || "")
				.split(",")
				.map(value => value.trim())
				.filter(value => /\/(32|128)$/.test(value))
				.map(value => value.replace(/\/(32|128)$/, ""))
		},
		canManage(){
			return this.capabilities?.capabilities?.supported === true && !this.loading && !this.applying
		},
		primaryActionLabel(){
			return this.previewRequired ? "Review changes" : "Apply reviewed changes"
		},
		primaryActionIcon(){
			return this.previewRequired ? "bi bi-eye" : "bi bi-shield-check"
		},
		policySignature(){
			return JSON.stringify(this.policy)
		},
		hasUnappliedChanges(){
			return this.policySignature !== this.persistedSignature
		},
		changeState(){
			if (this.loading) return "Loading policy state"
			if (!this.previewRequired && this.previewRuleset) return "Preview ready - confirm to apply"
			if (this.hasUnappliedChanges) return "Changes not applied"
			if (!this.hasPersistedPolicy) return "Not configured"
			return this.policy.managed ? "Applied" : "Disabled"
		},
		changeStateClass(){
			if (!this.previewRequired && this.previewRuleset) return "alert-info"
			if (this.hasUnappliedChanges) return "alert-warning"
			if (this.hasPersistedPolicy && this.policy.managed) return "alert-success"
			return "alert-secondary"
		},
		policyStateIcon(){
			if (!this.previewRequired && this.previewRuleset) return "bi bi-eye"
			if (this.hasUnappliedChanges) return "bi bi-pencil-square"
			if (this.hasPersistedPolicy && this.policy.managed) return "bi bi-shield-check"
			return "bi bi-shield"
		},
		peerKey(){
			const key = this.target.peer?.id || ""
			return key.length > 26 ? `${key.slice(0, 12)}...${key.slice(-10)}` : key
		},
		policyModeDescription(){
			return this.policy.managed
				? "Only the destinations below are allowed. All other forwarded traffic from this Peer is denied after application."
				: "Forwarding access control is off. This Peer keeps the gateway's existing forwarding behavior."
		}
	},
	watch: {
		policy: {
			deep: true,
			handler(){
				if (!this.loading){
					this.previewRequired = true
					this.previewRuleset = ""
					this.previewHash = ""
					this.disableConfirmation = false
				}
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
		this.tunnelAddress = this.tunnelAddresses.includes(this.target.tunnelAddress)
			? this.target.tunnelAddress
			: this.tunnelAddresses[0] || "";
		await Promise.all([this.loadCapabilities(), this.loadPolicy()]);
	},
	methods: {
		GetLocale,
		basePayload(){
			return {
				configuration_name: this.target.configurationName,
				peer_public_key: this.target.peer.id,
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
					this.hasPersistedPolicy = Boolean(res.data.policy);
					this.persistedSignature = JSON.stringify(this.policy);
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
		async runPrimaryAction(){
			if (this.previewRequired){
				await this.preview()
			}else{
				await this.apply()
			}
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
					this.disableConfirmation = false;
					this.loadPolicy();
					this.$emit("changed");
				}else{
					this.error = res.message;
				}
				this.applying = false;
			});
		},
		resetChanges(){
			this.policy = this.hasPersistedPolicy ? JSON.parse(this.persistedSignature) : emptyPolicy();
			this.previewRequired = true;
			this.previewRuleset = "";
			this.previewHash = "";
			this.disableConfirmation = false;
		},
		requestDeactivate(){
			this.disableConfirmation = !this.disableConfirmation;
		},
		async deactivate(){
			this.applying = true;
			await fetchPost("/api/networkPolicy/deactivate", this.basePayload(), (res) => {
				if (res.status){
					this.store.newMessage("WGDashboard", GetLocale("Network policy disabled"), "success");
					this.policy = emptyPolicy();
					this.previewRuleset = "";
					this.disableConfirmation = false;
					this.loadPolicy();
					this.$emit("changed");
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
					this.$emit("changed");
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
	<Teleport to="body">
		<div class="network-policy-overlay">
			<div class="dashboardModal network-policy-workbench bg-body shadow p-4 p-md-4">
				<div class="d-flex align-items-start gap-3 mb-3">
					<div class="policy-heading">
						<div class="policy-heading-icon"><i class="bi bi-shield-lock"></i></div>
						<div>
							<h5 class="mb-1"><LocaleText t="Network Policy" /></h5>
							<div class="small text-muted"><LocaleText t="Control this Peer's forwarded access without changing gateway services." /></div>
						</div>
					</div>
					<button type="button" class="btn-close ms-auto" :title="GetLocale('Close')" @click="$emit('close')"></button>
				</div>

			<div v-if="error" class="alert alert-danger py-2 small">{{ error }}</div>
			<div v-if="capabilities && !capabilities.capabilities?.supported" class="alert alert-warning py-2 small">
				{{ capabilities.capabilities?.message }}
			</div>

			<div class="policy-context mb-3">
				<div class="policy-context-item policy-context-peer">
					<span><LocaleText t="Peer" /></span>
					<strong>{{ target.peer.name || target.peer.id }}</strong>
				</div>
				<div class="policy-context-item">
					<span><LocaleText t="Configuration" /></span>
					<code>{{ target.configurationName || "-" }}</code>
				</div>
				<div class="policy-context-item">
					<span><LocaleText t="Peer tunnel address" /></span>
					<select class="form-select form-select-sm" v-model="tunnelAddress" :disabled="tunnelAddresses.length < 2">
						<option v-for="address in tunnelAddresses" :key="address" :value="address">{{ address }}</option>
					</select>
				</div>
				<div class="policy-context-item">
					<span><LocaleText t="Public Key" /></span>
					<code :title="target.peer.id">{{ peerKey }}</code>
				</div>
			</div>

			<div class="alert py-2 small d-flex align-items-center gap-2 mb-3" :class="changeStateClass">
				<i :class="policyStateIcon"></i>
				<div>
					<strong><LocaleText :t="changeState" /></strong>
					<span v-if="hasUnappliedChanges" class="ms-1"><LocaleText t="Editing does not change forwarding access. Review the change, then confirm application." /></span>
					<span v-else-if="!previewRequired && previewRuleset" class="ms-1"><LocaleText t="Review the generated rules below, then confirm application." /></span>
				</div>
			</div>

			<section class="policy-section mb-3">
				<div class="d-flex align-items-start gap-3">
					<div class="form-check form-switch m-0 pt-1">
						<input class="form-check-input" id="network-policy-managed" type="checkbox" v-model="policy.managed" @change="onManagedChange">
					</div>
					<div>
						<label class="form-check-label fw-semibold" for="network-policy-managed"><LocaleText t="Enable forwarded access control" /></label>
						<div class="small text-muted"><LocaleText :t="policyModeDescription" /></div>
					</div>
				</div>
			</section>

			<section v-if="policy.managed" class="policy-section mb-3">
				<div class="d-flex align-items-center gap-2 mb-1">
					<div>
						<h6 class="mb-0"><LocaleText t="Allowed destinations" /></h6>
						<div class="small text-muted"><LocaleText t="Add each network service this Peer may reach." /></div>
					</div>
					<button type="button" class="btn btn-sm btn-outline-primary ms-auto" :title="GetLocale('Add rule')" @click="addRule"><i class="bi bi-plus-lg"></i><span class="ms-1"><LocaleText t="Add rule" /></span></button>
				</div>
				<div v-for="(rule, index) in policy.rules" :key="index" class="rule-row">
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
				<div v-if="policy.rules.length === 0" class="empty-rules"><i class="bi bi-exclamation-triangle me-2"></i><LocaleText t="No destination is allowed. Applying this policy denies all forwarded traffic for this Peer." /></div>
			</section>

			<section class="policy-actions border-top pt-3">
				<div class="d-flex align-items-center gap-2 mb-2">
					<i class="bi bi-clipboard-check text-primary"></i>
					<div class="small text-muted"><LocaleText t="Review the rules, then confirm before applying them to the gateway." /></div>
				</div>
				<div class="d-flex flex-wrap gap-2">
					<button type="button" class="btn btn-primary" :disabled="!canManage" @click="runPrimaryAction"><i :class="[primaryActionIcon, 'me-1']"></i><LocaleText :t="primaryActionLabel"></LocaleText></button>
					<button v-if="hasUnappliedChanges || previewRuleset" type="button" class="btn btn-outline-secondary" :disabled="applying" @click="resetChanges"><i class="bi bi-arrow-counterclockwise me-1"></i><LocaleText t="Discard changes"></LocaleText></button>
					<div v-if="hasPersistedPolicy && policy.managed" class="ms-sm-auto d-flex gap-2">
						<button v-if="!disableConfirmation" type="button" class="btn btn-outline-danger" :disabled="!canManage" @click="requestDeactivate"><i class="bi bi-shield-x me-1"></i><LocaleText t="Disable policy"></LocaleText></button>
						<button v-else type="button" class="btn btn-danger" :disabled="!canManage" @click="deactivate"><i class="bi bi-exclamation-octagon me-1"></i><LocaleText t="Confirm disable"></LocaleText></button>
						<button v-if="disableConfirmation" type="button" class="btn btn-outline-secondary" :disabled="applying" @click="requestDeactivate"><LocaleText t="Cancel"></LocaleText></button>
					</div>
				</div>
			</section>

			<div v-if="previewRuleset" class="preview-panel mt-3">
				<div class="d-flex align-items-center gap-2 small fw-bold mb-1"><i class="bi bi-eye"></i><LocaleText t="Generated nftables rules" /> <code class="text-muted">{{ previewHash }}</code></div>
				<div class="small text-muted mb-2"><LocaleText t="These are the exact rules that will be applied after confirmation." /></div>
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
	</Teleport>
</template>

<style scoped>
.network-policy-overlay { position: fixed !important; inset: 0; z-index: 9999; overflow-y: auto; padding: 1rem; background-color: #00000060; backdrop-filter: blur(1px); -webkit-backdrop-filter: blur(1px); }
.network-policy-workbench { width: min(920px, 100%); min-height: 0; margin: 0 auto; }
.policy-heading { display: flex; align-items: center; gap: 0.75rem; }
.policy-heading-icon { display: grid; place-items: center; width: 2.4rem; height: 2.4rem; border: 1px solid var(--bs-primary-border-subtle); border-radius: 6px; color: var(--bs-primary); background: var(--bs-primary-bg-subtle); }
.policy-context { display: grid; grid-template-columns: minmax(150px, 1.25fr) repeat(3, minmax(120px, 1fr)); border: 1px solid var(--bs-border-color); border-radius: 6px; overflow: hidden; }
.policy-context-item { min-width: 0; padding: 0.6rem 0.75rem; border-left: 1px solid var(--bs-border-color); }
.policy-context-item:first-child { border-left: 0; }
.policy-context-item > span { display: block; margin-bottom: 0.2rem; color: var(--bs-secondary-color); font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
.policy-context-item strong, .policy-context-item code { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.policy-section { padding: 1rem; border: 1px solid var(--bs-border-color); border-radius: 6px; }
.rule-row { padding: 0.85rem 0; border-bottom: 1px solid var(--bs-border-color); }
.rule-row:last-of-type { border-bottom: 0; }
.empty-rules { margin-top: 0.75rem; padding: 0.7rem 0.8rem; border-left: 3px solid var(--bs-warning); background: var(--bs-warning-bg-subtle); color: var(--bs-warning-text-emphasis); font-size: 0.85rem; }
.preview-panel { padding: 0.85rem; border: 1px solid var(--bs-info-border-subtle); border-radius: 6px; background: var(--bs-info-bg-subtle); }
.ruleset-preview { max-height: 260px; overflow: auto; padding: 0.75rem; border: 1px solid var(--bs-border-color); background: var(--bs-tertiary-bg); font-size: 0.75rem; white-space: pre-wrap; }
@media (max-width: 768px) { .network-policy-overlay { padding: 0.5rem; } .policy-context { grid-template-columns: 1fr 1fr; } .policy-context-item:nth-child(3) { border-left: 0; border-top: 1px solid var(--bs-border-color); } .policy-context-item:nth-child(4) { border-top: 1px solid var(--bs-border-color); } }
@media (max-width: 460px) { .network-policy-overlay { padding: 0; } .network-policy-workbench { min-height: 100%; } .policy-context { grid-template-columns: 1fr; } .policy-context-item { border-left: 0; border-top: 1px solid var(--bs-border-color); } .policy-context-item:first-child { border-top: 0; } }
</style>
