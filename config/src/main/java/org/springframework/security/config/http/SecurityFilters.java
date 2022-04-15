/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.http;

/**
 * Stores the default order numbers of all Spring Security filters for use in
 * configuration.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Evgeniy Cheban
 */

enum SecurityFilters {

	FIRST(Integer.MIN_VALUE),

	DISABLE_ENCODE_URL_FILTER,

	FORCE_EAGER_SESSION_FILTER,

	CHANNEL_FILTER,

	SECURITY_CONTEXT_FILTER,

	CONCURRENT_SESSION_FILTER,

	WEB_ASYNC_MANAGER_FILTER,

	HEADERS_FILTER,

	CORS_FILTER,

	SAML2_LOGOUT_REQUEST_FILTER,

	SAML2_LOGOUT_RESPONSE_FILTER,

	CSRF_FILTER,

	SAML2_LOGOUT_FILTER,

	LOGOUT_FILTER,

	OAUTH2_AUTHORIZATION_REQUEST_FILTER,

	SAML2_AUTHENTICATION_REQUEST_FILTER,

	X509_FILTER,

	PRE_AUTH_FILTER,

	CAS_FILTER,

	OAUTH2_LOGIN_FILTER,

	SAML2_AUTHENTICATION_FILTER,

	FORM_LOGIN_FILTER,

	LOGIN_PAGE_FILTER,

	LOGOUT_PAGE_FILTER,

	DIGEST_AUTH_FILTER,

	BEARER_TOKEN_AUTH_FILTER,

	BASIC_AUTH_FILTER,

	REQUEST_CACHE_FILTER,

	SERVLET_API_SUPPORT_FILTER,

	JAAS_API_SUPPORT_FILTER,

	REMEMBER_ME_FILTER,

	ANONYMOUS_FILTER,

	OAUTH2_AUTHORIZATION_CODE_GRANT_FILTER,

	WELL_KNOWN_CHANGE_PASSWORD_REDIRECT_FILTER,

	SESSION_MANAGEMENT_FILTER,

	EXCEPTION_TRANSLATION_FILTER,

	FILTER_SECURITY_INTERCEPTOR,

	SWITCH_USER_FILTER,

	LAST(Integer.MAX_VALUE);

	private static final int INTERVAL = 100;

	private final int order;

	SecurityFilters() {
		this.order = ordinal() * INTERVAL;
	}

	SecurityFilters(int order) {
		this.order = order;
	}

	public int getOrder() {
		return this.order;
	}

}
