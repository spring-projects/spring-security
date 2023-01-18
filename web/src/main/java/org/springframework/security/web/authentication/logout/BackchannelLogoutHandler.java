/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.authentication.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

public final class BackchannelLogoutHandler implements LogoutHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private RestOperations rest = new RestTemplate();

	private String logoutEndpointName = "/logout";

	private String clientSessionCookieName = "JSESSIONID";

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		if (!(authentication instanceof BackchannelLogoutAuthentication token)) {
			if (this.logger.isDebugEnabled()) {
				String message = "Did not perform Backchannel Logout since authentication [%s] was of the wrong type";
				this.logger.debug(String.format(message, authentication.getClass().getSimpleName()));
			}
			return;
		}
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.COOKIE, this.clientSessionCookieName + "=" + token.getSessionId());
		CsrfToken csrfToken = token.getCsrfToken();
		if (csrfToken != null) {
			headers.add(csrfToken.getHeaderName(), csrfToken.getToken());
		}
		String url = request.getRequestURL().toString();
		String logout = UriComponentsBuilder.fromHttpUrl(url).replacePath(this.logoutEndpointName).build()
				.toUriString();
		HttpEntity<?> entity = new HttpEntity<>(null, headers);
		this.rest.postForEntity(logout, entity, Object.class);
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(String.format("Invalidated session [%s]", token.getSessionId()));
		}
	}

	public void setRestOperations(RestOperations rest) {
		Assert.notNull(rest, "rest cannot be null");
		this.rest = rest;
	}

	public void setLogoutEndpointName(String logoutEndpointName) {
		Assert.hasText(logoutEndpointName, "logoutEndpointName cannot be empty");
		this.logoutEndpointName = logoutEndpointName;
	}

	public void setClientSessionCookieName(String clientSessionCookieName) {
		Assert.hasText(clientSessionCookieName, "clientSessionCookieName cannot be empty");
		this.clientSessionCookieName = clientSessionCookieName;
	}

}
