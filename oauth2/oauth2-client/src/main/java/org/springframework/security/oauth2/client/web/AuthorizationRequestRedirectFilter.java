/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.AuthorizationRequest;
import org.springframework.security.oauth2.client.endpoint.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.core.endpoint.OAuth2Parameter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * This <code>Filter</code> initiates the authorization code grant or implicit grant flow
 * by redirecting the end-user's user-agent to the authorization server's <i>Authorization Endpoint</i>.
 *
 * <p>
 * It uses an {@link AuthorizationRequestUriBuilder} to build the <i>OAuth 2.0 Authorization Request</i>,
 * which is used as the redirect <code>URI</code> to the <i>Authorization Endpoint</i>.
 * The redirect <code>URI</code> will include the client identifier, requested scope(s), state,
 * response type, and a redirection URI which the authorization server will send the user-agent back to
 * once access is granted (or denied) by the end-user (resource owner).
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationRequest
 * @see AuthorizationRequestRepository
 * @see AuthorizationRequestUriBuilder
 * @see ClientRegistration
 * @see ClientRegistrationRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request (Authorization Code)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2">Section 4.2 Implicit Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2.1">Section 4.2.1 Authorization Request (Implicit)</a>
 */
public class AuthorizationRequestRedirectFilter extends OncePerRequestFilter {
	public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
	private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
	private final AntPathRequestMatcher authorizationRequestMatcher;
	private final ClientRegistrationRepository clientRegistrationRepository;
	private AuthorizationRequestUriBuilder authorizationRequestUriBuilder = new DefaultAuthorizationRequestUriBuilder();
	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
	private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();

	public AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository) {
		this(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI, clientRegistrationRepository);
	}

	public AuthorizationRequestRedirectFilter(
		String authorizationRequestBaseUri, ClientRegistrationRepository clientRegistrationRepository) {

		Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.authorizationRequestMatcher = new AntPathRequestMatcher(
			authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	public final void setAuthorizationRequestUriBuilder(AuthorizationRequestUriBuilder authorizationRequestUriBuilder) {
		Assert.notNull(authorizationRequestUriBuilder, "authorizationRequestUriBuilder cannot be null");
		this.authorizationRequestUriBuilder = authorizationRequestUriBuilder;
	}

	public final void setAuthorizationRequestRepository(AuthorizationRequestRepository authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.shouldRequestAuthorization(request, response)) {
			try {
				this.sendRedirectForAuthorization(request, response);
			} catch (Exception failed) {
				this.unsuccessfulRedirectForAuthorization(request, response, failed);
			}
			return;
		}

		filterChain.doFilter(request, response);
	}

	private boolean shouldRequestAuthorization(HttpServletRequest request, HttpServletResponse response) {
		return this.authorizationRequestMatcher.matches(request);
	}

	private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {

		String registrationId = this.authorizationRequestMatcher
			.extractUriTemplateVariables(request).get(REGISTRATION_ID_URI_VARIABLE_NAME);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
		}

		String redirectUriStr = this.expandRedirectUri(request, clientRegistration);

		Map<String,Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2Parameter.REGISTRATION_ID, clientRegistration.getRegistrationId());

		AuthorizationRequest.Builder builder;
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			builder = AuthorizationRequest.authorizationCode();
		} else if (AuthorizationGrantType.IMPLICIT.equals(clientRegistration.getAuthorizationGrantType())) {
			builder = AuthorizationRequest.implicit();
		} else {
			throw new IllegalArgumentException("Invalid Authorization Grant Type for Client Registration (" +
				clientRegistration.getRegistrationId() + "): " + clientRegistration.getAuthorizationGrantType());
		}
		AuthorizationRequest authorizationRequest = builder
				.clientId(clientRegistration.getClientId())
				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(redirectUriStr)
				.scopes(clientRegistration.getScopes())
				.state(this.stateGenerator.generateKey())
				.additionalParameters(additionalParameters)
				.build();

		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
			this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
		}

		URI redirectUri = this.authorizationRequestUriBuilder.build(authorizationRequest);
		this.authorizationRedirectStrategy.sendRedirect(request, response, redirectUri.toString());
	}

	private void unsuccessfulRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
														Exception failed) throws IOException, ServletException {

		if (logger.isDebugEnabled()) {
			logger.debug("Authorization Request failed: " + failed.toString(), failed);
		}
		response.sendError(HttpStatus.BAD_REQUEST.value(), HttpStatus.BAD_REQUEST.getReasonPhrase());
	}

	private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration) {
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("scheme", request.getScheme());
		uriVariables.put("serverName", request.getServerName());
		uriVariables.put("serverPort", String.valueOf(request.getServerPort()));
		uriVariables.put("contextPath", request.getContextPath());
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		String baseUrl = UriComponentsBuilder.newInstance()
			.scheme(request.getScheme())
			.host(request.getServerName())
			.port(request.getServerPort())
			.path(request.getContextPath())
			.build()
			.toUriString();
		uriVariables.put("baseUrl", baseUrl);

		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUri())
			.buildAndExpand(uriVariables)
			.toUriString();
	}
}
