<script>
import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import {fetchPost} from "@/utilities/fetch.js";
import LocaleText from "@/components/text/localeText.vue";

export default {
	name: "dashboardSessionSettings",
	components: {LocaleText},
	setup(){
		const store = DashboardConfigurationStore();
		return {store};
	},
	data(){
		return {
			lifetimeHours: 168,
			invalidFeedback: "",
			showInvalidFeedback: false,
			updating: false,
			changed: false,
		};
	},
	mounted(){
		this.lifetimeHours = Number(this.store.Configuration.Server.session_lifetime_hours);
	},
	methods: {
		async save(){
			if (!this.changed || this.updating) return;
			this.updating = true;
			await fetchPost("/api/updateDashboardConfigurationItem", {
				section: "Server",
				key: "session_lifetime_hours",
				value: this.lifetimeHours,
			}, (res) => {
				if (res.status){
					this.store.Configuration.Server.session_lifetime_hours = res.data;
					this.showInvalidFeedback = false;
				}else{
					this.showInvalidFeedback = true;
					this.invalidFeedback = res.message;
				}
				this.changed = false;
				this.updating = false;
			});
		},
	},
};
</script>

<template>
	<div>
		<label for="session_lifetime_hours" class="text-muted mb-1">
			<strong><small><LocaleText t="Trusted device session lifetime"></LocaleText></small></strong>
		</label>
		<div class="input-group">
			<input id="session_lifetime_hours"
			       type="number"
			       min="1"
			       max="8760"
			       class="form-control"
			       :class="{'is-invalid': showInvalidFeedback}"
			       v-model.number="lifetimeHours"
			       @input="changed = true"
			       @blur="save"
			       :disabled="updating">
			<span class="input-group-text"><LocaleText t="hours"></LocaleText></span>
			<div class="invalid-feedback">{{invalidFeedback}}</div>
		</div>
		<small class="text-muted">
			<LocaleText t="Trusted devices will not request TOTP again until this period expires."></LocaleText>
		</small>
	</div>
</template>
