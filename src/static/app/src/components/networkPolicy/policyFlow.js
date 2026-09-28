/**
 * Save-flow gating and labelling for the network policy modal.
 *
 * These predicates used to live inline in networkPolicyModal.vue, which is how the "turn forwarded
 * access control off and it cannot be saved" defect survived: the primary button was gated on "the
 * rules are valid", and a Peer being disabled has no rules by definition. Keeping them here makes
 * the one rule that matters testable - disabling access control is a change in its own right, so it
 * is saveable as soon as it differs from what the gateway currently has applied.
 */
import { isPolicyGroupsValid } from "./portGroups.js";

/**
 * Every locale key these helpers can hand back, declared once so the language-pack test
 * (tests/test_network_policy.py::NetworkPolicyLocaleTest) can demand a translation for it. Keys
 * rendered through a dynamic :t binding are invisible to the static regex over the modal.
 */
export const POLICY_FLOW_LOCALE_KEYS = [
	"Loading policy state",
	"Preview ready - confirm to apply",
	"Preview ready - confirm to disable",
	"Changes not applied",
	"Not configured",
	"Applied",
	"Disabled",
	"Save changes",
	"Apply changes",
	"Confirm disable",
	"Editing does not change forwarding access. Review the change, then confirm application.",
	"Editing does not change forwarding access. Review the change, then confirm disabling access control.",
	"Apply only after reviewing the generated rules.",
	"Confirm only after reviewing the generated rules.",
	"These are the exact rules that will be applied after confirmation.",
	"Forwarded access control will be turned off for this Peer. Its destination rules will be removed from the gateway.",
	"Review the generated rules below, then confirm application.",
	"Review the generated rules below, then confirm disabling access control."
];

const isManaged = (policy) => Boolean(policy && policy.managed);

const readState = (state = {}) => ({
	loading: Boolean(state.loading),
	managed: isManaged(state),
	previewReady: !state.previewRequired && Boolean(state.previewRuleset),
	hasUnappliedChanges: Boolean(state.hasUnappliedChanges),
	hasPersistedPolicy: Boolean(state.hasPersistedPolicy)
});

/** Whether the primary action may run right now. */
export const canReviewPolicy = (policy, hasUnappliedChanges = false) => {
	if (!isManaged(policy)) return Boolean(hasUnappliedChanges);
	return isPolicyGroupsValid(Array.isArray(policy.groups) ? policy.groups : []);
};

/** Label/icon of the single primary button, per step (generate the preview first, then confirm). */
export const primaryAction = (policy, previewRequired) => {
	if (previewRequired) return {label: "Save changes", icon: "bi bi-save"};
	return isManaged(policy)
		? {label: "Apply changes", icon: "bi bi-shield-check"}
		: {label: "Confirm disable", icon: "bi bi-shield-x"};
};

/** One sentence above the generated ruleset; it must not promise denial for a disable. */
export const reviewDescription = (policy) => (isManaged(policy)
	? "These are the exact rules that will be applied after confirmation."
	: "Forwarded access control will be turned off for this Peer. Its destination rules will be removed from the gateway.");

/**
 * The one-line nudge under the state badge while a preview waits for confirmation. Both steps are
 * "review then confirm", but what gets confirmed differs, and only one of them keeps enforcing.
 */
export const previewConfirmationHint = (policy) => (isManaged(policy)
	? "Review the generated rules below, then confirm application."
	: "Review the generated rules below, then confirm disabling access control.");

/**
 * The sub-line under the state badge while edits sit unapplied. It used to hard-code "confirm
 * application" for every case, so a Peer being switched off read "confirm application" one line
 * above a button that says "Confirm disable".
 */
export const unsavedChangesHint = (policy) => (isManaged(policy)
	? "Editing does not change forwarding access. Review the change, then confirm application."
	: "Editing does not change forwarding access. Review the change, then confirm disabling access control.");

/** Review tab footer, shown beside the primary button once a fresh preview exists. */
export const reviewConfirmationHint = (policy) => (isManaged(policy)
	? "Apply only after reviewing the generated rules."
	: "Confirm only after reviewing the generated rules.");

export const policyState = (state) => {
	const current = readState(state);
	if (current.loading) return "Loading policy state";
	if (current.previewReady) return current.managed ? "Preview ready - confirm to apply" : "Preview ready - confirm to disable";
	if (current.hasUnappliedChanges) return "Changes not applied";
	if (!current.hasPersistedPolicy) return "Not configured";
	return current.managed ? "Applied" : "Disabled";
};

export const policyStateClass = (state) => {
	const current = readState(state);
	if (current.previewReady) return "policy-state-info";
	if (current.hasUnappliedChanges) return "policy-state-warning";
	if (current.hasPersistedPolicy && current.managed) return "policy-state-success";
	return "policy-state-neutral";
};

export const policyStateIcon = (state) => {
	const current = readState(state);
	if (current.previewReady) return "bi bi-eye";
	if (current.hasUnappliedChanges) return "bi bi-pencil-square";
	if (current.hasPersistedPolicy && current.managed) return "bi bi-shield-check";
	return "bi bi-shield";
};
