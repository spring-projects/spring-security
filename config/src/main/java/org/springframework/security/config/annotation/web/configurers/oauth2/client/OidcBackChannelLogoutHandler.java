/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link LogoutHandler} that locates the sessions associated with a given OIDC
 * Back-Channel Logout Token and invalidates each one.
 *
 * @author Josh Cummings
 * @since 6.4
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel Logout
 * Spec</a>
 */
public final class OidcBackChannelLogoutHandler implements LogoutHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private final OidcSessionRegistry sessionRegistry;

	private RestOperations restOperations = new RestTemplate();

	private String logoutUri = "{baseUrl}/logout/connect/back-channel/{registrationId}";

	private String sessionCookieName = "JSESSIONID";

	private final OAuth2ErrorHttpMessageConverter errorHttpMessageConverter = new OAuth2ErrorHttpMessageConverter();

	public OidcBackChannelLogoutHandler(OidcSessionRegistry sessionRegistry) {
		this.sessionRegistry = sessionRegistry;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		if (!(authentication instanceof OidcBackChannelLogoutAuthentication token)) {
			if (this.logger.isDebugEnabled()) {
				String message = "Did not perform OIDC Back-Channel Logout since authentication [%s] was of the wrong type";
				this.logger.debug(String.format(message, authentication.getClass().getSimpleName()));
			}
			return;
		}
		Iterable<OidcSessionInformation> sessions = this.sessionRegistry.removeSessionInformation(token.getPrincipal());
		Collection<String> errors = new ArrayList<>();
		int totalCount = 0;
		int invalidatedCount = 0;
		for (OidcSessionInformation session : sessions) {
			totalCount++;
			try {
				eachLogout(request, token, session);
				invalidatedCount++;
			}
			catch (RestClientException ex) {
				this.logger.debug("Failed to invalidate session", ex);
				errors.add(ex.getMessage());
				this.sessionRegistry.saveSessionInformation(session);
			}
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(String.format("Invalidated %d out of %d sessions", invalidatedCount, totalCount));
		}
		if (!errors.isEmpty()) {
			handleLogoutFailure(response, oauth2Error(errors));
		}
	}

	private void eachLogout(HttpServletRequest request, OidcBackChannelLogoutAuthentication token,
			OidcSessionInformation session) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.COOKIE, this.sessionCookieName + "=" + session.getSessionId());
		for (Map.Entry<String, String> credential : session.getAuthorities().entrySet()) {
			headers.add(credential.getKey(), credential.getValue());
		}
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		String logout = computeLogoutEndpoint(request, token);
		MultiValueMap<String, String> body = new LinkedMultiValueMap();
		body.add("logout_token", token.getPrincipal().getTokenValue());
		body.add("_spring_security_internal_logout", "true");
		HttpEntity<?> entity = new HttpEntity<>(body, headers);
		this.restOperations.postForEntity(logout, entity, Object.class);
	}

	String computeLogoutEndpoint(HttpServletRequest request, OidcBackChannelLogoutAuthentication token) {
		// @formatter:off
		UriComponents uriComponents = UriComponentsBuilder
				.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.build();

		Map<String, String> uriVariables = new HashMap<>();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
		uriVariables.put("baseUrl", uriComponents.toUriString());

		String host = uriComponents.getHost();
		uriVariables.put("baseHost", (host != null) ? host : "");

		String path = uriComponents.getPath();
		uriVariables.put("basePath", (path != null) ? path : "");

		int port = uriComponents.getPort();
		uriVariables.put("basePort", (port == -1) ? "" : ":" + port);

		String registrationId = token.getClientRegistration().getRegistrationId();
		uriVariables.put("registrationId", registrationId);

		return UriComponentsBuilder.fromUriString(this.logoutUri)
				.buildAndExpand(uriVariables)
				.toUriString();
		// @formatter:on
	}

	private OAuth2Error oauth2Error(Collection<String> errors) {
		return new OAuth2Error("partial_logout", "not all sessions were terminated: " + errors,
				"https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
	}

	private void handleLogoutFailure(HttpServletResponse response, OAuth2Error error) {
		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
		try {
			this.errorHttpMessageConverter.write(error, null, new ServletServerHttpResponse(response));
		}
		catch (IOException ex) {
			throw new IllegalStateException(ex);
		}
	}

	/**
	 * Use this logout URI for performing per-session logout. Defaults to {@code /logout}
	 * since that is the default URI for
	 * {@link org.springframework.security.web.authentication.logout.LogoutFilter}.
	 * @param logoutUri the URI to use
	 */
	public void setLogoutUri(String logoutUri) {
		Assert.hasText(logoutUri, "logoutUri cannot be empty");
		this.logoutUri = logoutUri;
	}

	/**
	 * Use this cookie name for the session identifier. Defaults to {@code JSESSIONID}.
	 *
	 * <p>
	 * Note that if you are using Spring Session, this likely needs to change to SESSION.
	 * @param sessionCookieName the cookie name to use
	 */
	public void setSessionCookieName(String sessionCookieName) {
		Assert.hasText(sessionCookieName, "clientSessionCookieName cannot be empty");
		this.sessionCookieName = sessionCookieName;
	}

}
