import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import {GetLocale} from "@/utilities/locale.js";
import router from "@/router/router.js";
const getHeaders = () => {
	let headers = {
		"Content-Type": "application/json"
	}
	const store = DashboardConfigurationStore();
	const crossServer = store.getActiveCrossServer();
	if (crossServer){
		headers['wg-dashboard-apikey'] = crossServer.apiKey
        if (crossServer.headers){
            for (let header of Object.values(crossServer.headers)){
                if (header.key && header.value && !Object.keys(headers).includes(header.key)){
                    headers[header.key] = header.value
                }
            }
        }
	}


	return headers
}

export const getUrl = (url) => {
	const store = DashboardConfigurationStore();
	const apiKey = store.getActiveCrossServer();
	if (apiKey){
		return `${apiKey.host}${url}`
	}
	if (import.meta.env.MODE === 'development') {
		return url;
	}
	// const appPrefix = window.APP_PREFIX || '';
	return `./.${url}`;
}

const parseErrorBody = async (response) => {
	try {
		const body = await response.clone().json();
		if (body && typeof body === "object"){
			return body;
		}
	} catch (_){
		// non-JSON error body (HTML page, gateway error, ...)
	}
	return null;
}

const handleFailedResponse = async (response, callback) => {
	const store = DashboardConfigurationStore();
	const body = await parseErrorBody(response);
	if (response.status === 401){
		store.newMessage("WGDashboard", GetLocale("Sign in session ended, please sign in again"), "warning")
		await router.push({path: '/signin'})
	}
	const message = (body && body.message) || `Request failed (${response.status} ${response.statusText})`;
	const errorResponse = {
		status: false,
		message,
		data: body ? body.data : null
	};
	if (callback){
		callback(errorResponse);
	}
	return errorResponse;
}

const handleNetworkFailure = (error, callback) => {
	console.log("Error:", error);
	const errorResponse = {
		status: false,
		message: GetLocale("Network request failed. Please check your connection and try again.")
	};
	if (callback){
		callback(errorResponse);
	}
	return errorResponse;
}

export const fetchGet = async (url, params=undefined, callback=undefined) => {
	const urlSearchParams = new URLSearchParams(params);
	try {
		const response = await fetch(`${getUrl(url)}?${urlSearchParams.toString()}`, {
			headers: getHeaders()
		});
		if (!response.ok){
			await handleFailedResponse(response, callback);
			return undefined;
		}
		const body = await response.json();
		if (callback){
			callback(body);
		}
		return body;
	} catch (error){
		return handleNetworkFailure(error, callback);
	}
}

export const fetchPost = async (url, body, callback) => {
	try {
		const response = await fetch(`${getUrl(url)}`, {
			headers: getHeaders(),
			method: "POST",
			body: JSON.stringify(body)
		});
		if (!response.ok){
			await handleFailedResponse(response, callback);
			return undefined;
		}
		const json = await response.json();
		if (callback){
			callback(json);
		}
		return json;
	} catch (error){
		return handleNetworkFailure(error, callback);
	}
}
