import assert from "node:assert/strict";
import test from "node:test";

import {
	POLICY_FLOW_LOCALE_KEYS,
	canReviewPolicy,
	canSubmitPolicyChange,
	policyState,
	policyStateClass,
	policyStateIcon,
	previewConfirmationHint,
	primaryAction,
	reviewConfirmationHint,
	reviewDescription,
	unsavedChangesHint
} from "./policyFlow.js";

const managedPolicy = () => ({
	managed: true,
	groups: [{destination: "192.168.0.117/32", protocol: "tcp", allPorts: true, ports: []}]
});
const disabledPolicy = () => ({managed: false, groups: []});
const invalidPolicy = () => ({
	managed: true,
	groups: [{destination: "", protocol: "tcp", allPorts: false, ports: [{from: 443, to: 443}]}]
});

test("turning forwarded access control off is a saveable change on its own", () => {
	// The regression that made the switch look dead: a Peer being disabled has no rules, so
	// gating on "rules are valid" left the primary button permanently disabled.
	assert.equal(canReviewPolicy(disabledPolicy(), true), true);
	assert.equal(canReviewPolicy({managed: false, groups: [{destination: "bad", protocol: "tcp"}]}, true), true);
});

test("a Peer that was never configured cannot save an unchanged switch off", () => {
	assert.equal(canReviewPolicy(disabledPolicy(), false), false);
});

test("an enabled policy still needs valid destination groups", () => {
	assert.equal(canReviewPolicy(managedPolicy(), false), true);
	assert.equal(canReviewPolicy(managedPolicy(), true), true);
	assert.equal(canReviewPolicy(invalidPolicy(), true), false);
	// Zero destinations is a deliberate deny-all, not an error.
	assert.equal(canReviewPolicy({managed: true, groups: []}, true), true);
});

test("the primary button names the step it performs", () => {
	assert.deepEqual(primaryAction(managedPolicy(), true), {label: "Save changes", icon: "bi bi-save"});
	assert.deepEqual(primaryAction(disabledPolicy(), true), {label: "Save changes", icon: "bi bi-save"});
	assert.deepEqual(primaryAction(managedPolicy(), false), {label: "Apply changes", icon: "bi bi-shield-check"});
	assert.deepEqual(primaryAction(disabledPolicy(), false), {label: "Confirm disable", icon: "bi bi-shield-x"});
});

test("the state badge distinguishes an apply preview from a disable preview", () => {
	const base = {
		loading: false,
		previewRequired: false,
		previewRuleset: "flush table inet wgd_network_policy\nadd chain inet wgd_network_policy forward { ... }",
		hasUnappliedChanges: false,
		hasPersistedPolicy: true
	};
	assert.equal(policyState({...base, managed: true}), "Preview ready - confirm to apply");
	assert.equal(policyState({...base, managed: false}), "Preview ready - confirm to disable");
	assert.equal(policyStateClass({...base, managed: false}), "policy-state-info");
	assert.equal(policyStateIcon({...base, managed: false}), "bi bi-eye");

	assert.equal(policyState({...base, loading: true, managed: true}), "Loading policy state");
	assert.equal(policyState({...base, previewRequired: true, previewRuleset: "", managed: true}), "Applied");
	assert.equal(policyState({...base, previewRequired: true, previewRuleset: "", managed: false}), "Disabled");
	assert.equal(policyState({...base, previewRequired: true, previewRuleset: "", hasUnappliedChanges: true, managed: false}), "Changes not applied");
	// Precedence matters: an un-persisted Peer still shows "Not configured" only once there is
	// nothing pending; a pending edit wins with "Changes not applied".
	assert.equal(policyState({...base, previewRequired: true, previewRuleset: "", hasUnappliedChanges: false, hasPersistedPolicy: false, managed: false}), "Not configured");
});

test("the review panel never promises denial for a disable", () => {
	const disableText = reviewDescription(disabledPolicy());
	assert.doesNotMatch(disableText, /denied/i);
	assert.doesNotMatch(disableText, /exact rules/i);
	assert.equal(reviewDescription(managedPolicy()), "These are the exact rules that will be applied after confirmation.");
});

test("the confirmation nudge matches what the button will do", () => {
	assert.equal(previewConfirmationHint(managedPolicy()), "Review the generated rules below, then confirm application.");
	const hint = previewConfirmationHint(disabledPolicy());
	assert.match(hint, /disabling access control/);
	assert.doesNotMatch(hint, /confirm application/);
});

test("the badge sub-line and the review footer describe the click they precede", () => {
	assert.equal(unsavedChangesHint(managedPolicy()), "Editing does not change forwarding access. Review the change, then confirm application.");
	const disableEdit = unsavedChangesHint(disabledPolicy());
	assert.doesNotMatch(disableEdit, /confirm application/);
	assert.match(disableEdit, /confirm disabling access control/);
	assert.equal(reviewConfirmationHint(managedPolicy()), "Apply only after reviewing the generated rules.");
	const disableReview = reviewConfirmationHint(disabledPolicy());
	assert.doesNotMatch(disableReview, /\bApply\b/);
	assert.equal(disableReview, "Confirm only after reviewing the generated rules.");
});

test("every label handed to the template is a declared locale key", () => {
	const produced = new Set([
		...POLICY_FLOW_LOCALE_KEYS,
		primaryAction(managedPolicy(), true).label,
		primaryAction(managedPolicy(), false).label,
		primaryAction(disabledPolicy(), false).label,
		reviewDescription(managedPolicy()),
		reviewDescription(disabledPolicy()),
		previewConfirmationHint(managedPolicy()),
		previewConfirmationHint(disabledPolicy()),
		unsavedChangesHint(managedPolicy()),
		unsavedChangesHint(disabledPolicy()),
		reviewConfirmationHint(managedPolicy()),
		reviewConfirmationHint(disabledPolicy())
	]);
	for (const state of [
		{loading: true, managed: true},
		{loading: false, managed: true, previewRequired: false, previewRuleset: "flush table"},
		{loading: false, managed: false, previewRequired: false, previewRuleset: "flush table"},
		{loading: false, managed: false, previewRequired: true, previewRuleset: "", hasUnappliedChanges: true},
		{loading: false, managed: false, previewRequired: true, previewRuleset: "", hasUnappliedChanges: false, hasPersistedPolicy: false},
		{loading: false, managed: false, previewRequired: true, previewRuleset: "", hasUnappliedChanges: false, hasPersistedPolicy: true}
	]){
		produced.add(policyState(state));
	}
	assert.deepEqual([...produced].filter((key) => !POLICY_FLOW_LOCALE_KEYS.includes(key)), []);
	assert.equal(new Set(POLICY_FLOW_LOCALE_KEYS).size, POLICY_FLOW_LOCALE_KEYS.length);
});

test("the primary button stays gated by the tab it sits on", () => {
	// Rules tab: a switch turned off is clickable on its own merit...
	assert.equal(canSubmitPolicyChange({step: "rules", canManage: true, canReview: canReviewPolicy(disabledPolicy(), true), previewRuleset: "", hasUnappliedChanges: true}), true);
	// ...and a managed Peer with broken destination groups is not.
	assert.equal(canSubmitPolicyChange({step: "rules", canManage: true, canReview: canReviewPolicy(invalidPolicy(), true), previewRuleset: "", hasUnappliedChanges: true}), false);
	// While the modal is loading or applying, nothing is clickable in either step.
	assert.equal(canSubmitPolicyChange({step: "rules", canManage: false, canReview: true, previewRuleset: "flush table inet wgd_network_policy", hasUnappliedChanges: false}), false);
	assert.equal(canSubmitPolicyChange({step: "review", canManage: false, canReview: true, previewRuleset: "flush table inet wgd_network_policy", hasUnappliedChanges: false}), false);
	// Review tab: a generated ruleset is what makes the confirm click honest.
	assert.equal(canSubmitPolicyChange({step: "review", canManage: true, canReview: canReviewPolicy(managedPolicy(), false), previewRuleset: "flush table inet wgd_network_policy", hasUnappliedChanges: false}), true);
	assert.equal(canSubmitPolicyChange({step: "review", canManage: true, canReview: canReviewPolicy(disabledPolicy(), true), previewRuleset: "flush table inet wgd_network_policy", hasUnappliedChanges: false}), true);
	// The whole point of the extra clause: no preview and nothing pending means there is nothing to
	// confirm, so the button must not promise a review that never happened.
	assert.equal(canSubmitPolicyChange({step: "review", canManage: true, canReview: true, previewRuleset: "", hasUnappliedChanges: false}), false);
	// An un-previewed edit still submits from the review tab, because that click regenerates it.
	assert.equal(canSubmitPolicyChange({step: "review", canManage: true, canReview: true, previewRuleset: "", hasUnappliedChanges: true}), true);
	// Unknown or omitted step falls back to the stricter rule instead of handing out a live button.
	assert.equal(canSubmitPolicyChange({canManage: true, canReview: true, previewRuleset: "", hasUnappliedChanges: false}), false);
	assert.equal(canSubmitPolicyChange({step: "history", canManage: true, canReview: true, previewRuleset: "", hasUnappliedChanges: false}), false);
	assert.equal(canSubmitPolicyChange(), false);
});
