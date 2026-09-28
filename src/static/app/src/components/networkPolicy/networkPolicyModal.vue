<script>
import {fetchGet, fetchPost} from "@/utilities/fetch.js";
import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import LocaleText from "@/components/text/localeText.vue";
import {GetLocale} from "@/utilities/locale.js";
import {
	emptyPort,
	emptyPortGroup,
	flattenGroups,
	groupRules,
	portLabel,
	validatePolicyGroups
} from "@/components/networkPolicy/portGroups.js";
// The save-flow predicates live in policyFlow.js, where node:test can reach them without a
// browser. They are imported under describe* aliases so the computed names used by the template
// stay unchanged.
import {
	canReviewPolicy,
	previewConfirmationHint as describePreviewConfirmationHint,
	primaryAction,
	policyState as describePolicyState,
	policyStateClass as describePolicyStateClass,
	policyStateIcon as describePolicyStateIcon,
	reviewConfirmationHint as describeReviewConfirmationHint,
	reviewDescription as describeReviewDescription,
	unsavedChangesHint as describeUnsavedChangesHint
} from "@/components/networkPolicy/policyFlow.js";

const emptyPolicy = () => ({managed: false, groups: []});

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
			persistedPolicy: null,
			persistedSignature: "",
			disableConfirmation: false,
			suppressTunnelAddressWatch: false,
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
			// Turning forwarded access control off is a saveable change in its own right: the API
			// accepts managed=false and rejects rules alongside it, so there is nothing left to
			// validate. It still has to be a real change, otherwise a Peer that was never
			// configured gets a pointless deactivate revision. That is exactly the rule the
			// old inline version broke: a Peer being disabled has no rules to validate, so the
			// button stayed dead and the switch looked unsavable.
			return canReviewPolicy(this.policy, this.hasUnappliedChanges);
		},
		allPortsRuleCount(){
			return this.policy.groups.filter((group) => group.protocol !== "icmp" && group.allPorts).length;
		},
		primaryActionStep(){
			return primaryAction(this.policy, this.previewRequired)
		},
		primaryActionLabel(){
			// Confirming a removal says "Confirm disable"; labelling it "Apply changes" tells the
			// operator the opposite of what the next click does.
			return this.primaryActionStep.label
		},
		primaryActionIcon(){
			return this.primaryActionStep.icon
		},
		previewStale(){
			return this.previewRequired && Boolean(this.previewRuleset)
		},
		reviewHint(){
			if (this.previewStale) return "The rules have changed since the last review. Save again to regenerate the preview."
			if (this.previewRuleset) return describeReviewConfirmationHint(this.policy)
			return "Save changes to generate the exact nftables rules."
		},
		reviewDescriptionText(){
			// Disabling still generates a real ruleset (flush + chains), so this panel renders for
			// it too - it just must not promise that traffic "will be denied".
			return describeReviewDescription(this.policy)
		},
		previewConfirmHint(){
			return describePreviewConfirmationHint(this.policy)
		},
		unsavedChangesHintText(){
			// Same objection as the review footer: what sits under the badge must describe the click
			// the operator is about to make, and for a switched-off Peer that click removes rules.
			return describeUnsavedChangesHint(this.policy)
		},
		policySignature(){
			return this.projectSignature(this.policy)
		},
		hasUnappliedChanges(){
			return this.policySignature !== this.persistedSignature
		},
		policyFlowState(){
			// One snapshot handed to the three helpers below, so the badge wording, colour and
			// icon can never disagree with each other again.
			return {
				loading: this.loading,
				managed: this.policy.managed,
				previewRequired: this.previewRequired,
				previewRuleset: this.previewRuleset,
				hasUnappliedChanges: this.hasUnappliedChanges,
				hasPersistedPolicy: this.hasPersistedPolicy
			}
		},
		changeState(){
			return describePolicyState(this.policyFlowState)
		},
		changeStateClass(){
			return describePolicyStateClass(this.policyFlowState)
		},
		policyStateIcon(){
			return describePolicyStateIcon(this.policyFlowState)
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
					this.disableConfirmation = false
				}
			}
		},
		tunnelAddress(newAddress, oldAddress){
			if (this.suppressTunnelAddressWatch){
				this.suppressTunnelAddressWatch = false
				return
			}
			if (this.loading || newAddress === oldAddress){
				return
			}
			if (this.hasUnappliedChanges
				&& !window.confirm(GetLocale("You have unsaved changes. Switching the tunnel address will discard them. Continue?"))){
				this.suppressTunnelAddressWatch = true
				this.tunnelAddress = oldAddress
				return
			}
			this.previewRequired = true
			this.loadPolicy()
		}
	},
	async mounted(){
		this.tunnelAddress = this.tunnelAddresses.includes(this.target.tunnelAddress)
			? this.target.tunnelAddress
			: this.tunnelAddresses[0] || "";
		await Promise.all([this.loadCapabilities(), this.loadPolicy()]);
		if (!this.hasPersistedPolicy && this.policy.groups.length === 0){
			this.activeTab = "rules";
		}
	},
	methods: {
		GetLocale,
		projectSignature(policy){
			return JSON.stringify({
				managed: Boolean(policy.managed),
				groups: (policy.groups || []).map((group) => ({
					destination: group.destination,
					protocol: group.protocol,
					allPorts: Boolean(group.allPorts),
					ports: (group.ports || []).map((port) => ({from: port.from, to: port.to}))
				}))
			})
		},
		basePayload(){
			return {
				configuration_name: this.target.configurationName,
				peer_public_key: this.target.peer.id,
				tunnel_address: this.tunnelAddress,
				managed: this.policy.managed,
				rules: flattenGroups(this.policy.groups)
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
					const stored = res.data.policy;
					this.policy = stored
						? {managed: Boolean(stored.managed), groups: groupRules(stored.rules)}
						: emptyPolicy();
					this.hasPersistedPolicy = Boolean(stored);
					this.persistedPolicy = JSON.parse(JSON.stringify(this.policy));
					this.persistedSignature = this.projectSignature(this.policy);
					this.revisions = res.data.revisions || [];
					this.previewRequired = true;
					this.previewRuleset = "";
				}else{
					this.error = res.message;
				}
				this.loading = false;
			});
		},
		addGroup(){
			if (!this.policy.managed){
				this.policy.managed = true
			}
			this.policy.groups.push(emptyPortGroup())
		},
		onManagedChange(){
			if (!this.policy.managed){
				if (this.policy.groups.length
					&& !window.confirm(GetLocale("Turn off forwarded access control? The destination groups in this window will be cleared."))){
					this.policy.managed = true;
					return;
				}
				this.policy.groups = [];
			}
		},
		removeGroup(index){
			this.policy.groups.splice(index, 1);
		},
		addPort(group, range = false){
			group.ports.push({...emptyPort(), showRange: range});
		},
		removePort(group, index){
			group.ports.splice(index, 1);
		},
		onAllPortsChange(group){
			group.touched = true;
			if (group.allPorts){
				group.ports = [];
			}else if (!group.ports.length){
				group.ports = [emptyPort()];
			}
		},
		onProtocolChange(group){
			group.touched = true;
			if (group.protocol === "icmp"){
				group.allPorts = false;
				group.ports = [];
			}else if (!group.ports.length){
				group.allPorts = false;
				group.ports = [emptyPort()];
			}
		},
		groupValidation(groupIndex){
			return validatePolicyGroups(this.policy.groups)[groupIndex] || {groupError: "", portErrors: []};
		},
		groupError(groupIndex){
			const group = this.policy.groups[groupIndex];
			if (!group || !group.touched) return "";
			return this.groupValidation(groupIndex).groupError;
		},
		portError(groupIndex, portIndex){
			const group = this.policy.groups[groupIndex];
			if (!group || !group.touched) return "";
			return this.groupValidation(groupIndex).portErrors[portIndex] || "";
		},
		markTouched(group){
			group.touched = true;
		},
		portGroupSummary(group){
			if (group.protocol === "icmp") return GetLocale("No ports for ICMP");
			if (group.allPorts) return GetLocale("All ports");
			return group.ports.map(portLabel).join(", ");
		},
		flattenedRuleCount(group){
			return flattenGroups([group]).length;
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
			for (const group of this.policy.groups){
				group.touched = true;
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
			if (!this.canReview){
				this.error = GetLocale("Review the rules, then confirm before applying them to the gateway.")
				return
			}
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
					// managed=false goes through this same endpoint, so the toast has to
					// say "disabled" or it contradicts the revision history it just wrote.
					this.store.newMessage("WGDashboard", GetLocale(this.policy.managed ? "Network policy applied" : "Network policy disabled"), "success");
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
			this.policy = this.persistedPolicy ? JSON.parse(JSON.stringify(this.persistedPolicy)) : emptyPolicy();
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
			if (!window.confirm(GetLocale("Roll back to this revision? The current policy will be replaced."))) return;
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
					<span v-if="hasUnappliedChanges" class="ms-1"><LocaleText :t="unsavedChangesHintText" /></span>
					<span v-else-if="!previewRequired && previewRuleset" class="ms-1"><LocaleText :t="previewConfirmHint" /></span>
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
				<div v-if="policy.managed && policy.groups.length" class="policy-overview-note mt-3"><i class="bi bi-info-circle"></i><span><LocaleText t="Each configured destination also permits ICMP diagnostics for that destination." /></span></div>
			</section>
			<section class="policy-section policy-rules-section mb-3" :class="{'policy-section-disabled': !policy.managed}">
				<div class="d-flex align-items-center gap-2 mb-1">
					<div>
						<h6 class="mb-0"><LocaleText t="Allowed destinations" /></h6>
						<div class="small text-muted"><LocaleText t="Add each network service this Peer may reach." /></div>
					</div>
					<button type="button" class="btn btn-sm btn-outline-primary ms-auto" :disabled="!canManage" :title="GetLocale('Add destination group')" @click="addGroup"><i class="bi bi-plus-lg"></i><span class="ms-1"><LocaleText t="Add destination group" /></span></button>
				</div>
				<fieldset :disabled="!policy.managed || !canManage" class="policy-rules-fieldset">
				<div v-for="(group, groupIndex) in policy.groups" :key="group.uid" class="policy-target-group">
					<div class="policy-target-group-head">
						<input class="form-control policy-dest-input" :class="{'is-invalid': groupError(groupIndex)}" v-model.trim="group.destination" placeholder="192.168.0.117/32" :aria-label="GetLocale('Destination IP or CIDR')" @blur="markTouched(group)">
						<select class="form-select policy-proto-select" :aria-label="GetLocale('Protocol')" v-model="group.protocol" @change="onProtocolChange(group)"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select>
						<label v-if="group.protocol !== 'icmp'" class="form-check m-0 policy-allports-check" :title="GetLocale('Allow every port on this destination')">
							<input class="form-check-input" type="checkbox" v-model="group.allPorts" @change="onAllPortsChange(group)">
							<span class="form-check-label"><LocaleText t="All ports" /></span>
						</label>
						<button type="button" class="btn btn-outline-danger policy-group-remove" :title="GetLocale('Remove destination group')" @click="removeGroup(groupIndex)"><i class="bi bi-trash"></i></button>
					</div>
					<div v-if="groupError(groupIndex)" class="invalid-feedback d-block policy-group-error">{{ GetLocale(groupError(groupIndex)) }}</div>
					<div v-if="group.protocol === 'icmp'" class="policy-target-group-body policy-target-group-body-muted"><i class="bi bi-activity me-1"></i><LocaleText t="No ports for ICMP" /></div>
					<div v-else-if="group.allPorts" class="policy-target-group-body policy-target-group-body-muted"><i class="bi bi-infinity me-1"></i><LocaleText t="All ports are allowed for this destination." /></div>
					<div v-else class="policy-target-group-body">
						<div class="policy-target-ports-label"><LocaleText t="Ports" /></div>
						<div class="policy-port-grid">
						<div v-for="(port, portIndex) in group.ports" :key="port.uid" class="policy-port-chip">
							<input class="form-control policy-port-from" :class="{'is-invalid': portError(groupIndex, portIndex)}" type="number" min="1" max="65535" v-model.number="port.from" :placeholder="GetLocale('From')" @blur="markTouched(group)">
							<span v-if="port.showRange" class="policy-port-dash">–</span>
							<input v-if="port.showRange" class="form-control policy-port-to" :class="{'is-invalid': portError(groupIndex, portIndex)}" type="number" min="1" max="65535" v-model.number="port.to" :placeholder="GetLocale('To')" @blur="markTouched(group)">
								<button v-else type="button" class="btn btn-outline-secondary policy-port-range-toggle" :title="GetLocale('Use port range')" @click="port.showRange = true"><i class="bi bi-arrows-expand"></i></button>
								<button type="button" class="btn btn-outline-danger policy-port-remove" :title="GetLocale('Remove port')" @click="removePort(group, portIndex)"><i class="bi bi-trash"></i></button>
								<div v-if="portError(groupIndex, portIndex)" class="invalid-feedback d-block policy-port-error">{{ GetLocale(portError(groupIndex, portIndex)) }}</div>
							</div>
							<button type="button" class="btn btn-sm btn-outline-primary policy-port-add" :title="GetLocale('Add port')" @click="addPort(group)"><i class="bi bi-plus-lg"></i><span class="ms-1"><LocaleText t="Add port" /></span></button>
							<button type="button" class="btn btn-sm btn-outline-secondary policy-port-add-range" :title="GetLocale('Add port range')" @click="addPort(group, true)"><i class="bi bi-arrows-expand"></i><span class="ms-1"><LocaleText t="Add port range" /></span></button>
						</div>
						<div class="form-text mt-2 mb-0"><LocaleText t="Leave the end port empty to allow one port." /></div>
					</div>
				</div>
				</fieldset>
				<div v-if="!policy.managed" class="empty-rules empty-rules-muted"><i class="bi bi-slash-circle me-2"></i><LocaleText t="Enable forwarded access control to configure allowed destinations." /></div>
				<div v-else-if="policy.groups.length === 0" class="empty-rules"><i class="bi bi-exclamation-triangle me-2"></i><LocaleText t="No destination is allowed. Applying this policy denies all forwarded traffic for this Peer." /></div>
				<div v-else class="small text-muted mt-2"><i class="bi bi-activity me-1"></i><LocaleText t="ICMP diagnostics are allowed for every configured destination." /></div>
			</section>
			<section class="policy-tab-actions policy-rules-actions">
				<div class="small text-muted"><i class="bi bi-save text-primary me-1"></i><LocaleText t="Save changes to generate the exact nftables rules, then apply them after review." /></div>
				<div class="d-flex flex-wrap gap-2 ms-auto">
					<button type="button" class="btn btn-primary" :disabled="!canManage || !canReview" @click="runPrimaryAction"><i :class="[primaryActionIcon, 'me-1']"></i><LocaleText :t="primaryActionLabel"></LocaleText></button>
					<button v-if="hasUnappliedChanges || previewRuleset" type="button" class="btn btn-outline-secondary" :disabled="applying" @click="resetChanges"><i class="bi bi-arrow-counterclockwise me-1"></i><LocaleText t="Discard changes"></LocaleText></button>
				</div>
			</section>
			</div>

			<div v-if="activeTab === 'review'" class="policy-tab-panel" role="tabpanel">
			<div v-if="previewStale" class="policy-notice policy-notice-warning mb-3"><i class="bi bi-exclamation-triangle"></i><LocaleText t="The rules have changed since the last review. Save again to regenerate the preview." /></div>
			<div v-if="previewRuleset" class="preview-panel mb-3" :class="{'preview-stale': previewStale}">
				<div class="preview-heading">
					<div><i :class="policy.managed ? 'bi bi-eye' : 'bi bi-shield-x'"></i><strong><LocaleText t="Generated nftables rules" /></strong></div>
					<code>{{ previewHash }}</code>
				</div>
				<div class="preview-description"><LocaleText :t="reviewDescriptionText" /></div>
				<div class="policy-checks small mb-2">
					<div><i class="bi bi-check-circle-fill text-success me-2"></i><LocaleText t="nftables syntax check passed in an isolated temporary table. No live forwarding rule was changed." /></div>
					<div><i class="bi bi-shield-check text-primary me-2"></i><LocaleText t="Scope is limited to forwarded traffic from this Peer. Gateway SSH and WireGuard listener traffic are not changed." /></div>
					<div v-if="allPortsRuleCount" class="text-warning-emphasis"><i class="bi bi-exclamation-triangle-fill me-2"></i><LocaleText t="One or more rules allow all ports. Confirm that this broad access is intended." /></div>
					<div v-if="policy.managed"><i class="bi bi-shield-x text-warning-emphasis me-2"></i><LocaleText t="All other forwarded traffic from this Peer will be denied after application." /></div>
					<div v-if="policy.managed"><i class="bi bi-activity text-success me-2"></i><LocaleText t="ICMP diagnostics are allowed for every configured destination." /></div>
				</div>
				<div v-if="policy.groups.length" class="policy-group-summary mb-2">
					<strong><LocaleText t="Port group summary" /></strong>
					<div v-for="(group, groupIndex) in policy.groups" :key="group.uid" class="policy-group-summary-row">
						<code>{{ group.destination }}</code><span class="badge text-bg-secondary">{{ group.protocol.toUpperCase() }}</span><span>{{ portGroupSummary(group) }}</span><span class="text-muted">{{ flattenedRuleCount(group) }} <LocaleText t="flattened rules" /></span>
					</div>
				</div>
				<pre class="ruleset-preview mb-0">{{ previewRuleset }}</pre>
			</div>

			<div v-else class="empty-rules empty-rules-muted"><i class="bi bi-clipboard2 me-2"></i><LocaleText t="Save changes to generate the exact nftables rules." /></div>

			<section class="policy-tab-actions policy-review-actions">
				<div class="small text-muted"><i :class="[previewStale ? 'bi bi-exclamation-triangle' : (previewRuleset ? 'bi bi-shield-check' : 'bi bi-clipboard-check'), 'text-primary me-1']"></i><LocaleText :t="reviewHint" /></div>
				<div class="d-flex flex-wrap gap-2 ms-auto">
					<button type="button" class="btn btn-primary" :disabled="!canManage || !canReview || (!previewRuleset && !hasUnappliedChanges)" @click="runPrimaryAction"><i :class="[primaryActionIcon, 'me-1']"></i><LocaleText :t="primaryActionLabel"></LocaleText></button>
					<button v-if="hasUnappliedChanges || previewRuleset" type="button" class="btn btn-outline-secondary" :disabled="applying" @click="resetChanges"><i class="bi bi-arrow-counterclockwise me-1"></i><LocaleText t="Discard changes" /></button>
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
.policy-target-group { padding: 0.6rem 0.7rem; margin-bottom: 0.6rem; border: 1px solid var(--bs-border-color); border-radius: 7px; background: var(--bs-secondary-bg); }
.policy-target-group-head { display: flex; flex-wrap: wrap; gap: 0.45rem; align-items: center; }
.policy-target-group-head .form-control, .policy-target-group-head .form-select { min-height: 2.375rem; }
.policy-dest-input { flex: 1 1 180px; max-width: 360px; min-width: 0; }
.policy-proto-select { width: 5.5rem; }
.policy-allports-check { white-space: nowrap; }
.policy-allports-check .form-check-label { font-size: 0.85rem; }
.policy-group-remove { display: inline-grid; width: 2.375rem; place-items: center; padding: 0; }
.policy-group-error { margin-top: 0.45rem; }
.policy-target-group-body { margin: 0.55rem 0 0.2rem; padding: 0.6rem 0.7rem 0.65rem; border: 1px solid var(--bs-border-color); border-radius: 6px; background: var(--bs-body-bg); }
.policy-target-group-body-muted { color: var(--bs-secondary-color); font-size: 0.85rem; }
.policy-target-ports-label { font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--bs-secondary-color); margin-bottom: 0.4rem; }
.policy-port-grid { display: flex; flex-wrap: wrap; gap: 0.45rem; align-items: center; }
.policy-port-chip { display: flex; flex-wrap: wrap; gap: 0.3rem; align-items: center; }
.policy-port-from, .policy-port-to { width: 4.7rem; min-height: 2.375rem; appearance: textfield; -moz-appearance: textfield; }
.policy-port-from::-webkit-outer-spin-button, .policy-port-from::-webkit-inner-spin-button, .policy-port-to::-webkit-outer-spin-button, .policy-port-to::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.policy-port-dash { align-self: center; color: var(--bs-secondary-color); font-weight: 600; }
.policy-port-range-toggle, .policy-port-remove { display: inline-grid; width: 2.375rem; min-height: 2.375rem; place-items: center; padding: 0; }
.policy-port-error { flex-basis: 100%; }
.policy-port-add, .policy-port-add-range { white-space: nowrap; }
.preview-stale { opacity: 0.65; }
.empty-rules { margin-top: 0.75rem; padding: 0.7rem 0.8rem; border-left: 3px solid var(--bs-warning); background: var(--bs-warning-bg-subtle); color: var(--bs-warning-text-emphasis); font-size: 0.85rem; }
.empty-rules-muted { border-left-color: var(--bs-secondary-color); background: var(--bs-secondary-bg); color: var(--bs-secondary-color); }
.preview-panel { padding: 1rem; color: var(--bs-body-color); border: 1px solid var(--bs-border-color); border-radius: 7px; background: var(--bs-tertiary-bg); }
.preview-heading { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; color: var(--bs-emphasis-color); font-size: 0.88rem; }
.preview-heading strong { margin-left: 0.45rem; }
.preview-heading code { overflow-wrap: anywhere; color: var(--bs-secondary-color); font-size: 0.7rem; text-align: right; }
.preview-description { margin: 0.45rem 0 0.75rem; color: var(--bs-secondary-color); font-size: 0.8rem; }
.policy-checks { display: grid; gap: 0.4rem; padding: 0.7rem; color: var(--bs-body-color); border: 1px solid var(--bs-border-color); border-radius: 6px; background: var(--bs-body-bg); }
.policy-group-summary { display: grid; gap: 0.4rem; padding: 0.7rem; border: 1px solid var(--bs-border-color); border-radius: 6px; background: var(--bs-body-bg); font-size: 0.8rem; }
.policy-group-summary-row { display: flex; flex-wrap: wrap; align-items: center; gap: 0.45rem; }
.policy-group-summary-row code { overflow-wrap: anywhere; color: var(--bs-emphasis-color); }
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
@media (max-width: 768px) { .network-policy-overlay { padding: 0.5rem; } .policy-target { grid-template-columns: 1fr; gap: 0.85rem; } .policy-tabs { gap: 0.25rem; } .policy-tab { flex: 0 0 auto; } .policy-dest-input { flex-basis: 100%; max-width: none; } }
@media (max-width: 460px) { .network-policy-overlay { padding: 0; } .network-policy-workbench { min-height: 100%; border-radius: 0; } }
</style>
