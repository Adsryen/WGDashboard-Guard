<script>
import {fetchGet, fetchPost} from "@/utilities/fetch.js";
import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import LocaleText from "@/components/text/localeText.vue";
import {GetLocale} from "@/utilities/locale.js";

const emptyPolicy = () => ({managed: false, rules: []});

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
			activeTab: "overview",
			policy: emptyPolicy(),
			tunnelAddress: "",
			capabilities: null,
			revisions: [],
			expandedRevisionId: "",
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
		modalTheme(){
			return this.store.Configuration?.Server?.dashboard_theme || "dark";
		},
		tunnelAddresses(){
			const explicitAddresses = Array.isArray(this.target.tunnelAddresses)
				? this.target.tunnelAddresses
				: [];
			const peerAddresses = String(this.target.peer?.allowed_ip || "")
				.split(",")
				.map(value => value.trim())
				.filter(value => /\/(32|128)$/.test(value))
				.map(value => value.replace(/\/(32|128)$/, ""));
			return [...new Set([...explicitAddresses, ...peerAddresses].filter(Boolean))];
		},
		canManage(){
			return this.capabilities?.capabilities?.supported === true && !this.loading && !this.applying
		},
		canReview(){
			if (!this.policy.managed) return false;
			const hasValidRules = this.policy.rules.every((rule) => {
				if (!rule.destination || !rule.protocol) return false;
				if (rule.protocol === "icmp") return rule.ports === null;
				if (rule.ports === null) return true;
				return Number.isInteger(rule.ports?.from) && Number.isInteger(rule.ports?.to)
					&& rule.ports.from >= 1 && rule.ports.to >= rule.ports.from && rule.ports.to <= 65535;
			});
			return hasValidRules;
		},
		allPortsRuleCount(){
			return this.policy.rules.filter((rule) => rule.protocol !== "icmp" && rule.ports === null).length;
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
			if (!this.previewRequired && this.previewRuleset) return "policy-state-info"
			if (this.hasUnappliedChanges) return "policy-state-warning"
			if (this.hasPersistedPolicy && this.policy.managed) return "policy-state-success"
			return "policy-state-neutral"
		},
		policyStateIcon(){
			if (!this.previewRequired && this.previewRuleset) return "bi bi-eye"
			if (this.hasUnappliedChanges) return "bi bi-pencil-square"
			if (this.hasPersistedPolicy && this.policy.managed) return "bi bi-shield-check"
			return "bi bi-shield"
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
		onProtocolChange(rule){
			if (rule.protocol === "icmp") rule.ports = null;
		},
		async copyPeerKey(){
			const peerKey = this.target.peer?.id || "";
			if (!peerKey) return;
			try {
				await navigator.clipboard.writeText(peerKey);
				this.store.newMessage("WGDashboard", GetLocale("Peer public key copied"), "success");
			} catch (_) {
				const input = document.createElement("textarea");
				input.value = peerKey;
				document.body.appendChild(input);
				input.select();
				document.execCommand("copy");
				input.remove();
				this.store.newMessage("WGDashboard", GetLocale("Peer public key copied"), "success");
			}
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
					this.activeTab = "review";
				}else{
					this.error = res.message;
				}
			});
		},
		async runPrimaryAction(){
			if (!this.canReview) return;
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
		},
		toggleRevision(revisionId){
			this.expandedRevisionId = this.expandedRevisionId === revisionId ? "" : revisionId;
		},
		revisionPortLabel(rule){
			if (rule.protocol === "icmp") return GetLocale("No ports for ICMP");
			if (rule.ports === null) return GetLocale("All ports");
			return rule.ports.from === rule.ports.to
				? String(rule.ports.from)
				: `${rule.ports.from}-${rule.ports.to}`;
		}
	}
}
</script>

<template>
	<Teleport to="body">
		<div class="network-policy-overlay" :data-bs-theme="modalTheme">
			<div class="dashboardModal network-policy-workbench bg-body shadow p-4 p-md-4">
				<header class="policy-header">
					<div class="policy-heading">
						<div class="policy-heading-icon"><i class="bi bi-shield-lock"></i></div>
						<div class="policy-heading-copy">
							<h5><LocaleText t="Network Policy" /></h5>
							<p><LocaleText t="Control this Peer's forwarded access without changing gateway services." /></p>
						</div>
					</div>
					<button type="button" class="btn-close ms-auto" :title="GetLocale('Close')" @click="$emit('close')"></button>
				</header>

			<div v-if="error" class="policy-notice policy-notice-danger"><i class="bi bi-exclamation-octagon"></i>{{ error }}</div>
			<div v-if="capabilities && !capabilities.capabilities?.supported" class="policy-notice policy-notice-warning">
				<i class="bi bi-exclamation-triangle"></i>
				{{ capabilities.capabilities?.message }}
			</div>

			<nav class="policy-tabs mb-3" role="tablist" :aria-label="GetLocale('Network policy sections')">
				<button type="button" class="policy-tab" :class="{active: activeTab === 'overview'}" role="tab" :aria-selected="activeTab === 'overview'" @click="activeTab = 'overview'"><i class="bi bi-layout-text-sidebar-reverse"></i><span><LocaleText t="Overview" /></span></button>
				<button type="button" class="policy-tab" :class="{active: activeTab === 'rules'}" role="tab" :aria-selected="activeTab === 'rules'" @click="activeTab = 'rules'"><i class="bi bi-signpost-split"></i><span><LocaleText t="Access rules" /></span></button>
				<button type="button" class="policy-tab" :class="{active: activeTab === 'review'}" role="tab" :aria-selected="activeTab === 'review'" @click="activeTab = 'review'"><i class="bi bi-clipboard-check"></i><span><LocaleText t="Review and history" /></span></button>
			</nav>

			<div v-if="activeTab === 'overview'" class="policy-tab-panel" role="tabpanel">
			<section class="policy-target mb-3">
				<div class="policy-target-identity">
					<span class="policy-field-label"><LocaleText t="Peer" /></span>
					<strong>{{ target.peer.name || target.peer.id }}</strong>
					<div class="policy-target-meta"><LocaleText t="Configuration" /> <code>{{ target.configurationName || "-" }}</code></div>
				</div>
				<label class="policy-address-control">
					<span class="policy-field-label"><LocaleText t="Peer tunnel address" /></span>
					<select class="form-select" v-model="tunnelAddress" :disabled="loading || tunnelAddresses.length === 0">
						<option v-for="address in tunnelAddresses" :key="address" :value="address">{{ address }}</option>
					</select>
				</label>
				<div class="policy-key-row">
					<div class="min-w-0">
						<span class="policy-field-label"><LocaleText t="Peer public key" /></span>
						<code class="policy-key" :title="target.peer.id">{{ target.peer.id }}</code>
					</div>
					<button type="button" class="btn btn-sm btn-outline-secondary policy-copy-button" :title="GetLocale('Copy peer public key')" @click="copyPeerKey"><i class="bi bi-copy"></i><span class="ms-1"><LocaleText t="Copy" /></span></button>
				</div>
			</section>

			<div class="policy-state mb-3" :class="changeStateClass">
				<i :class="policyStateIcon"></i>
				<div>
					<strong><LocaleText :t="changeState" /></strong>
					<span v-if="hasUnappliedChanges" class="ms-1"><LocaleText t="Editing does not change forwarding access. Review the change, then confirm application." /></span>
					<span v-else-if="!previewRequired && previewRuleset" class="ms-1"><LocaleText t="Review the generated rules below, then confirm application." /></span>
				</div>
			</div>

			<section class="policy-tab-actions policy-overview-actions">
				<div v-if="hasPersistedPolicy && policy.managed" class="d-flex flex-wrap justify-content-end gap-2 ms-auto">
					<button v-if="!disableConfirmation" type="button" class="btn btn-outline-danger" :disabled="!canManage" @click="requestDeactivate"><i class="bi bi-shield-x me-1"></i><LocaleText t="Disable policy"></LocaleText></button>
					<button v-else type="button" class="btn btn-danger" :disabled="!canManage" @click="deactivate"><i class="bi bi-exclamation-octagon me-1"></i><LocaleText t="Confirm disable"></LocaleText></button>
					<button v-if="disableConfirmation" type="button" class="btn btn-outline-secondary" :disabled="applying" @click="requestDeactivate"><LocaleText t="Cancel"></LocaleText></button>
				</div>
			</section>
			</div>

			<div v-if="activeTab === 'rules'" class="policy-tab-panel" role="tabpanel">
			<section class="policy-section policy-switch-section mb-3">
				<div class="d-flex align-items-start gap-3">
					<div class="form-check form-switch m-0 pt-1">
						<input class="form-check-input" id="network-policy-managed" type="checkbox" v-model="policy.managed" :disabled="!canManage" @change="onManagedChange">
					</div>
					<div>
						<label class="form-check-label fw-semibold" for="network-policy-managed"><LocaleText t="Enable forwarded access control" /></label>
						<div class="small text-muted"><LocaleText :t="policyModeDescription" /></div>
					</div>
				</div>
				<div class="policy-overview-note mt-3"><i class="bi bi-info-circle"></i><span><LocaleText t="Each configured destination also permits ICMP diagnostics for that destination." /></span></div>
			</section>
			<section class="policy-section policy-rules-section mb-3" :class="{'policy-section-disabled': !policy.managed}">
				<div class="d-flex align-items-center gap-2 mb-1">
					<div>
						<h6 class="mb-0"><LocaleText t="Allowed destinations" /></h6>
						<div class="small text-muted"><LocaleText t="Add each network service this Peer may reach." /></div>
					</div>
					<button type="button" class="btn btn-sm btn-outline-primary ms-auto" :disabled="!policy.managed" :title="GetLocale('Add rule')" @click="addRule"><i class="bi bi-plus-lg"></i><span class="ms-1"><LocaleText t="Add rule" /></span></button>
				</div>
				<fieldset :disabled="!policy.managed" class="policy-rules-fieldset">
				<div v-for="(rule, index) in policy.rules" :key="index" class="rule-row">
					<div class="row g-2 align-items-end">
						<div class="col-12 col-md-5">
							<label class="form-label small"><LocaleText t="Destination IP or CIDR"></LocaleText></label>
							<input class="form-control" v-model.trim="rule.destination" placeholder="192.168.10.117/32">
						</div>
						<div class="col-6 col-md-2">
							<label class="form-label small"><LocaleText t="Protocol"></LocaleText></label>
							<select class="form-select" v-model="rule.protocol" @change="onProtocolChange(rule)"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select>
						</div>
						<div class="col-5 col-md-3">
							<label class="form-label small"><LocaleText t="Ports"></LocaleText></label>
							<div v-if="rule.protocol === 'icmp'" class="form-control text-muted"><LocaleText t="No ports for ICMP"></LocaleText></div>
							<div v-else-if="rule.ports === null" class="form-control text-muted"><LocaleText t="All ports"></LocaleText></div>
							<div v-else class="d-flex gap-1"><input class="form-control" type="number" min="1" max="65535" v-model.number="rule.ports.from" :placeholder="GetLocale('From')"><input class="form-control" type="number" min="1" max="65535" v-model.number="rule.ports.to" :placeholder="GetLocale('To')"></div>
						</div>
						<div class="col-1 col-md-2 d-flex justify-content-end gap-1 rule-actions">
							<button v-if="rule.protocol !== 'icmp'" type="button" class="btn btn-outline-secondary" :title="GetLocale(rule.ports === null ? 'Use port range' : 'Allow all ports')" @click="setAllPorts(rule, rule.ports !== null)"><i :class="rule.ports === null ? 'bi bi-list-ol' : 'bi bi-infinity'"></i></button>
							<button type="button" class="btn btn-outline-danger" :title="GetLocale('Remove rule')" @click="removeRule(index)"><i class="bi bi-trash"></i></button>
						</div>
					</div>
				</div>
				</fieldset>
				<div v-if="!policy.managed" class="empty-rules empty-rules-muted"><i class="bi bi-slash-circle me-2"></i><LocaleText t="Enable forwarded access control to configure allowed destinations." /></div>
				<div v-else-if="policy.rules.length === 0" class="empty-rules"><i class="bi bi-exclamation-triangle me-2"></i><LocaleText t="No destination is allowed. Applying this policy denies all forwarded traffic for this Peer." /></div>
				<div v-else class="small text-muted mt-2"><i class="bi bi-activity me-1"></i><LocaleText t="ICMP diagnostics are allowed for every configured destination." /></div>
			</section>
			<section class="policy-tab-actions policy-rules-actions">
				<div class="small text-muted"><i class="bi bi-clipboard-check text-primary me-1"></i><LocaleText t="Review the rules, then confirm before applying them to the gateway." /></div>
				<div class="d-flex flex-wrap gap-2 ms-auto">
					<button type="button" class="btn btn-primary" :disabled="!canManage || !canReview" @click="runPrimaryAction"><i :class="[primaryActionIcon, 'me-1']"></i><LocaleText :t="primaryActionLabel"></LocaleText></button>
					<button v-if="hasUnappliedChanges || previewRuleset" type="button" class="btn btn-outline-secondary" :disabled="applying" @click="resetChanges"><i class="bi bi-arrow-counterclockwise me-1"></i><LocaleText t="Discard changes"></LocaleText></button>
				</div>
			</section>
			</div>

			<div v-if="activeTab === 'review'" class="policy-tab-panel" role="tabpanel">
			<div v-if="previewRuleset" class="preview-panel mb-3">
				<div class="preview-heading">
					<div><i class="bi bi-eye"></i><strong><LocaleText t="Generated nftables rules" /></strong></div>
					<code>{{ previewHash }}</code>
				</div>
				<div class="preview-description"><LocaleText t="These are the exact rules that will be applied after confirmation." /></div>
				<div class="policy-checks small mb-2">
					<div><i class="bi bi-check-circle-fill text-success me-2"></i><LocaleText t="nftables syntax check passed in an isolated temporary table. No live forwarding rule was changed." /></div>
					<div><i class="bi bi-shield-check text-primary me-2"></i><LocaleText t="Scope is limited to forwarded traffic from this Peer. Gateway SSH and WireGuard listener traffic are not changed." /></div>
					<div v-if="allPortsRuleCount" class="text-warning-emphasis"><i class="bi bi-exclamation-triangle-fill me-2"></i><LocaleText t="One or more rules allow all ports. Confirm that this broad access is intended." /></div>
					<div><i class="bi bi-shield-x text-warning-emphasis me-2"></i><LocaleText t="All other forwarded traffic from this Peer will be denied after application." /></div>
					<div><i class="bi bi-activity text-success me-2"></i><LocaleText t="ICMP diagnostics are allowed for every configured destination." /></div>
				</div>
				<pre class="ruleset-preview mb-0">{{ previewRuleset }}</pre>
			</div>

			<div v-else class="empty-rules empty-rules-muted"><i class="bi bi-clipboard2 me-2"></i><LocaleText t="Review changes to generate the exact nftables rules." /></div>

			<section class="policy-tab-actions policy-review-actions">
				<div class="small text-muted"><i :class="[previewRuleset ? 'bi bi-shield-check' : 'bi bi-clipboard-check', 'text-primary me-1']"></i><LocaleText :t="previewRuleset ? 'Apply only after reviewing the generated rules.' : 'Review changes to generate the exact nftables rules.'" /></div>
				<div v-if="previewRuleset" class="d-flex flex-wrap gap-2 ms-auto">
					<button type="button" class="btn btn-primary" :disabled="!canManage || previewRequired" @click="runPrimaryAction"><i class="bi bi-shield-check me-1"></i><LocaleText t="Apply reviewed changes"></LocaleText></button>
					<button type="button" class="btn btn-outline-secondary" :disabled="applying" @click="resetChanges"><i class="bi bi-arrow-counterclockwise me-1"></i><LocaleText t="Discard changes"></LocaleText></button>
				</div>
			</section>

			<div v-if="revisions.length" class="policy-history" :class="{'mt-4': previewRuleset}">
				<h6><LocaleText t="Policy history"></LocaleText></h6>
				<div v-for="revision in revisions" :key="revision.revision_id" class="policy-history-entry">
					<div class="policy-history-row">
						<span class="policy-history-status" :class="revision.status === 'applied' ? 'policy-history-status-success' : revision.status === 'failed' ? 'policy-history-status-danger' : 'policy-history-status-warning'">{{ GetLocale(revision.status) }}</span>
						<span>v{{ revision.version }} · {{ GetLocale(revision.action) }}</span>
						<code>{{ revision.hash }}</code>
						<button type="button" class="btn btn-sm btn-outline-secondary" :title="GetLocale(expandedRevisionId === revision.revision_id ? 'Hide rule snapshot' : 'Show rule snapshot')" @click="toggleRevision(revision.revision_id)"><i :class="expandedRevisionId === revision.revision_id ? 'bi bi-chevron-up' : 'bi bi-chevron-down'"></i></button>
						<button type="button" class="btn btn-sm btn-outline-secondary" :title="GetLocale('Restore this revision')" :disabled="applying" @click="rollback(revision.revision_id)"><i class="bi bi-arrow-counterclockwise"></i></button>
					</div>
					<div v-if="expandedRevisionId === revision.revision_id" class="policy-history-snapshot">
						<div class="policy-history-mode"><i :class="revision.policy.managed ? 'bi bi-shield-check' : 'bi bi-shield-x'"></i><span><LocaleText :t="revision.policy.managed ? 'Forwarded access control enabled' : 'Forwarded access control disabled'" /></span><span class="ms-auto"><LocaleText t="ICMP follows configured destinations" /></span></div>
						<div v-if="revision.policy.rules.length" class="policy-history-rules">
							<div v-for="(rule, index) in revision.policy.rules" :key="`${revision.revision_id}-${index}`" class="policy-history-rule">
								<code>{{ rule.destination }}</code><span class="badge text-bg-secondary">{{ rule.protocol.toUpperCase() }}</span><span class="text-muted">{{ revisionPortLabel(rule) }}</span>
							</div>
						</div>
						<div v-else class="small text-muted"><LocaleText t="No explicit destination rules" /></div>
					</div>
				</div>
			</div>
			</div>
			</div>
		</div>
	</Teleport>
</template>

<style scoped>
.network-policy-overlay { position: fixed !important; inset: 0; z-index: 9999; overflow-y: auto; padding: 1.5rem; background-color: rgb(0 0 0 / 45%); backdrop-filter: blur(2px); -webkit-backdrop-filter: blur(2px); }
.network-policy-workbench { width: min(1170px, 100%); min-height: 0; margin: 0 auto; color: var(--bs-body-color); border: 1px solid var(--bs-border-color); border-radius: 8px; }
.policy-header { display: flex; align-items: center; gap: 0.85rem; margin-bottom: 1.4rem; padding-bottom: 1rem; border-bottom: 1px solid var(--bs-border-color); }
.policy-heading { display: flex; min-width: 0; align-items: center; gap: 0.75rem; }
.policy-heading-copy { min-width: 0; }
.policy-heading-copy h5 { margin: 0; color: var(--bs-emphasis-color); font-size: 1rem; font-weight: 650; }
.policy-heading-copy p { margin: 0.2rem 0 0; color: var(--bs-secondary-color); font-size: 0.8rem; line-height: 1.35; }
.policy-heading-icon { display: grid; flex: 0 0 auto; place-items: center; width: 2.35rem; height: 2.35rem; border: 1px solid var(--bs-primary-border-subtle); border-radius: 6px; color: var(--bs-primary); background: var(--bs-primary-bg-subtle); }
.policy-target { display: grid; grid-template-columns: minmax(0, 1fr) minmax(190px, 0.8fr); gap: 1rem; align-items: end; padding: 1rem; color: var(--bs-body-color); border: 1px solid var(--bs-border-color); border-radius: 7px; background: var(--bs-tertiary-bg); }
.policy-target-identity { min-width: 0; }
.policy-field-label { display: block; margin-bottom: 0.3rem; color: var(--bs-secondary-color); font-size: 0.72rem; font-weight: 600; }
.policy-target-identity strong { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.policy-target-meta { margin-top: 0.35rem; color: var(--bs-secondary-color); font-size: 0.8rem; }
.policy-target-meta code { margin-left: 0.3rem; color: var(--bs-emphasis-color); }
.policy-address-control { min-width: 0; }
.policy-address-control select { min-height: 2.25rem; font-family: var(--bs-font-monospace); }
.policy-key-row { grid-column: 1 / -1; display: flex; align-items: end; gap: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--bs-border-color); }
.policy-key-row > div { min-width: 0; flex: 1; }
.policy-key { display: block; overflow-wrap: anywhere; color: var(--bs-secondary-color); font-size: 0.72rem; line-height: 1.45; }
.policy-copy-button { flex: 0 0 auto; }
.policy-state { display: flex; align-items: flex-start; gap: 0.65rem; padding: 0.75rem 0.9rem; color: var(--bs-body-color); border: 1px solid var(--bs-border-color); border-radius: 7px; background: var(--bs-tertiary-bg); font-size: 0.86rem; }
.policy-state > i { margin-top: 0.1rem; }
.policy-state-neutral { color: var(--bs-secondary-color); }
.policy-state-info { color: var(--bs-info-text-emphasis); border-color: var(--bs-info-border-subtle); background: var(--bs-info-bg-subtle); }
.policy-state-warning { color: var(--bs-warning-text-emphasis); border-color: var(--bs-warning-border-subtle); background: var(--bs-warning-bg-subtle); }
.policy-state-success { color: var(--bs-success-text-emphasis); border-color: var(--bs-success-border-subtle); background: var(--bs-success-bg-subtle); }
.policy-tabs { display: flex; gap: 0.35rem; padding: 0.35rem; overflow-x: auto; border: 1px solid var(--bs-border-color); border-radius: 7px; background: var(--bs-tertiary-bg); }
.policy-tab { display: inline-flex; flex: 1 0 max-content; align-items: center; justify-content: center; gap: 0.45rem; min-height: 2.4rem; padding: 0.45rem 0.8rem; color: var(--bs-secondary-color); border: 1px solid transparent; border-radius: 5px; background: transparent; font-size: 0.84rem; font-weight: 600; }
.policy-tab:hover { color: var(--bs-emphasis-color); background: var(--bs-secondary-bg); }
.policy-tab.active { color: var(--bs-primary); border-color: var(--bs-primary-border-subtle); background: var(--bs-body-bg); box-shadow: 0 1px 2px rgb(0 0 0 / 8%); }
.policy-tab:focus-visible { outline: 2px solid var(--bs-primary); outline-offset: 1px; }
.policy-tab-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; margin-top: 1rem; }
.policy-overview-actions { justify-content: flex-end; }
.policy-rules-actions, .policy-review-actions { padding-top: 1rem; border-top: 1px solid var(--bs-border-color); }
.policy-overview-note { display: flex; align-items: flex-start; gap: 0.55rem; padding: 0.8rem 0.9rem; color: var(--bs-secondary-color); border-left: 3px solid var(--bs-primary); background: var(--bs-primary-bg-subtle); font-size: 0.84rem; }
.policy-overview-note > i { color: var(--bs-primary); }
.policy-notice { display: flex; align-items: flex-start; gap: 0.55rem; margin-bottom: 1rem; padding: 0.7rem 0.85rem; border: 1px solid; border-radius: 7px; font-size: 0.85rem; }
.policy-notice > i { margin-top: 0.1rem; }
.policy-notice-danger { color: var(--bs-danger-text-emphasis); border-color: var(--bs-danger-border-subtle); background: var(--bs-danger-bg-subtle); }
.policy-notice-warning { color: var(--bs-warning-text-emphasis); border-color: var(--bs-warning-border-subtle); background: var(--bs-warning-bg-subtle); }
.policy-section { padding: 1rem; border: 1px solid var(--bs-border-color); border-radius: 7px; background: var(--bs-tertiary-bg); }
.policy-switch-section { background: var(--bs-body-bg); }
.policy-rules-section { padding-bottom: 0.4rem; }
.policy-rules-fieldset { min-width: 0; margin: 0; padding: 0; border: 0; }
.policy-section-disabled { opacity: 0.64; background: var(--bs-secondary-bg); }
.rule-row { padding: 0.85rem 0; border-bottom: 1px solid var(--bs-border-color); }
.rule-row:last-of-type { border-bottom: 0; }
.rule-row .form-control, .rule-row .form-select, .rule-actions .btn { min-height: 2.375rem; }
.rule-actions .btn { display: inline-grid; width: 2.375rem; place-items: center; padding: 0; }
.empty-rules { margin-top: 0.75rem; padding: 0.7rem 0.8rem; border-left: 3px solid var(--bs-warning); background: var(--bs-warning-bg-subtle); color: var(--bs-warning-text-emphasis); font-size: 0.85rem; }
.empty-rules-muted { border-left-color: var(--bs-secondary-color); background: var(--bs-secondary-bg); color: var(--bs-secondary-color); }
.preview-panel { padding: 1rem; color: var(--bs-body-color); border: 1px solid var(--bs-border-color); border-radius: 7px; background: var(--bs-tertiary-bg); }
.preview-heading { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; color: var(--bs-emphasis-color); font-size: 0.88rem; }
.preview-heading strong { margin-left: 0.45rem; }
.preview-heading code { overflow-wrap: anywhere; color: var(--bs-secondary-color); font-size: 0.7rem; text-align: right; }
.preview-description { margin: 0.45rem 0 0.75rem; color: var(--bs-secondary-color); font-size: 0.8rem; }
.policy-checks { display: grid; gap: 0.4rem; padding: 0.7rem; color: var(--bs-body-color); border: 1px solid var(--bs-border-color); border-radius: 6px; background: var(--bs-body-bg); }
.ruleset-preview { max-height: 260px; overflow: auto; padding: 0.75rem; color: var(--bs-body-color); border: 1px solid var(--bs-border-color); border-radius: 4px; background: var(--bs-body-bg); font-size: 0.75rem; white-space: pre-wrap; }
.policy-history { padding-top: 1rem; border-top: 1px solid var(--bs-border-color); }
.policy-history h6 { color: var(--bs-emphasis-color); }
.policy-history-entry { border-bottom: 1px solid var(--bs-border-color); }
.policy-history-row { display: flex; align-items: center; gap: 0.5rem; padding: 0.7rem 0; color: var(--bs-body-color); font-size: 0.8rem; }
.policy-history-row code { min-width: 0; overflow: hidden; color: var(--bs-secondary-color); text-overflow: ellipsis; white-space: nowrap; }
.policy-history-row code { flex: 1; }
.policy-history-snapshot { display: grid; gap: 0.55rem; margin: 0 0 0.75rem; padding: 0.75rem; border: 1px solid var(--bs-border-color); border-radius: 6px; background: var(--bs-body-bg); font-size: 0.8rem; }
.policy-history-mode { display: flex; flex-wrap: wrap; align-items: center; gap: 0.45rem; color: var(--bs-secondary-color); }
.policy-history-mode > i { color: var(--bs-primary); }
.policy-history-rules { display: grid; gap: 0.35rem; }
.policy-history-rule { display: flex; flex-wrap: wrap; align-items: center; gap: 0.45rem; padding-top: 0.45rem; border-top: 1px solid var(--bs-border-color); }
.policy-history-rule code { overflow-wrap: anywhere; color: var(--bs-emphasis-color); }
.policy-history-status { flex: 0 0 auto; font-weight: 600; }
.policy-history-status-success { color: var(--bs-success-text-emphasis); }
.policy-history-status-warning { color: var(--bs-warning-text-emphasis); }
.policy-history-status-danger { color: var(--bs-danger-text-emphasis); }
@media (max-width: 768px) { .network-policy-overlay { padding: 0.5rem; } .policy-target { grid-template-columns: 1fr; gap: 0.85rem; } .policy-tabs { gap: 0.25rem; } .policy-tab { flex: 0 0 auto; } }
@media (max-width: 460px) { .network-policy-overlay { padding: 0; } .network-policy-workbench { min-height: 100%; border-radius: 0; } }
</style>
