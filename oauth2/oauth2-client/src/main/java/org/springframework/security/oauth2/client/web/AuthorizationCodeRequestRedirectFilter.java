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

import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.endpoint.OAuth2Parameter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestVariablesExtractor;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * This <code>Filter</code> initiates the authorization code grant flow by redirecting
 * the end-user's user-agent to the authorization server's <i>Authorization Endpoint</i>.
 *
 * <p>
 * It uses an {@link AuthorizationRequestUriBuilder} to build the <i>OAuth 2.0 Authorization Request</i>,
 * which is used as the redirect <code>URI</code> to the <i>Authorization Endpoint</i>.
 * The redirect <code>URI</code> will include the client identifier, requested scope(s), state, response type, and a redirection URI
 * which the authorization server will send the user-agent back to (handled by {@link AuthorizationCodeAuthenticationProcessingFilter})
 * once access is granted (or denied) by the end-user (resource owner).
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationRequestAttributes
 * @see AuthorizationRequestRepository
 * @see AuthorizationRequestUriBuilder
 * @see ClientRegistration
 * @see ClientRegistrationRepository
 * @see AuthorizationCodeAuthenticationProcessingFilter
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 */
public class AuthorizationCodeRequestRedirectFilter extends OncePerRequestFilter {
	public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization/code";
	public static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
	public static final String DEFAULT_AUTHORIZATION_REQUEST_URI = DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}";
	private RequestMatcher authorizationRequestMatcher;
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final AuthorizationRequestUriBuilder authorizationUriBuilder;
	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
	private final StringKeyGenerator stateGenerator = new DefaultStateGenerator();
	private AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();

	public AuthorizationCodeRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository,
													AuthorizationRequestUriBuilder authorizationUriBuilder) {

		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizationUriBuilder, "authorizationUriBuilder cannot be null");
		this.authorizationRequestMatcher = new AntPathRequestMatcher(DEFAULT_AUTHORIZATION_REQUEST_URI);
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizationUriBuilder = authorizationUriBuilder;
	}

	public final <T extends RequestMatcher & RequestVariablesExtractor> void setAuthorizationRequestMatcher(T authorizationRequestMatcher) {
		Assert.notNull(authorizationRequestMatcher, "authorizationRequestMatcher cannot be null");
		this.authorizationRequestMatcher = authorizationRequestMatcher;
	}

	public final void setAuthorizationRequestRepository(AuthorizationRequestRepository authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.shouldRequestAuthorizationCode(request, response)) {
			try {
				this.sendRedirectForAuthorizationCode(request, response);
			} catch (Exception failed) {
				this.unsuccessfulRedirectForAuthorizationCode(request, response, failed);
			}
			return;
		}

		filterChain.doFilter(request, response);
	}

	protected boolean shouldRequestAuthorizationCode(HttpServletRequest request, HttpServletResponse response) {
		return this.authorizationRequestMatcher.matches(request);
	}

	protected void sendRedirectForAuthorizationCode(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {

		String registrationId = ((RequestVariablesExtractor)this.authorizationRequestMatcher)
				.extractUriTemplateVariables(request).get(REGISTRATION_ID_URI_VARIABLE_NAME);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			throw new IllegalArgumentException("Invalid Client Identifier (Registration Id): " + registrationId);
		}

		String redirectUriStr = this.expandRedirectUri(request, clientRegistration);

		Map<String,Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2Parameter.REGISTRATION_ID, clientRegistration.getRegistrationId());

		AuthorizationRequestAttributes authorizationRequestAttributes =
			AuthorizationRequestAttributes.withAuthorizationCode()
				.clientId(clientRegistration.getClientId())
				.authorizeUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(redirectUriStr)
				.scope(clientRegistration.getScope())
				.state(this.stateGenerator.generateKey())
				.additionalParameters(additionalParameters)
				.build();

		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequestAttributes, request, response);

		URI redirectUri = this.authorizationUriBuilder.build(authorizationRequestAttributes);
		this.authorizationRedirectStrategy.sendRedirect(request, response, redirectUri.toString());
	}

	protected void unsuccessfulRedirectForAuthorizationCode(HttpServletRequest request, HttpServletResponse response,
															Exception failed) throws IOException, ServletException {

		if (logger.isDebugEnabled()) {
			logger.debug("Authorization Request failed: " + failed.toString(), failed);
		}
		response.sendError(HttpServletResponse.SC_BAD_REQUEST, failed.getMessage());
	}

	private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration) {
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("scheme", request.getScheme());
		uriVariables.put("serverName", request.getServerName());
		uriVariables.put("serverPort", String.valueOf(request.getServerPort()));
		uriVariables.put("contextPath", request.getContextPath());
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUri())
			.buildAndExpand(uriVariables)
			.toUriString();
	}
}
