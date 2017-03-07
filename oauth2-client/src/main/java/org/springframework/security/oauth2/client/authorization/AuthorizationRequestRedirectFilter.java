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
package org.springframework.security.oauth2.client.authorization;

import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.DefaultStateGenerator;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;


/**
 * Initiates an OAuth 2.0 Authorization Request redirect for the Authorization Code Grant and Implicit Grant flows.
 *
 * @author Joe Grandja
 */
public class AuthorizationRequestRedirectFilter extends OncePerRequestFilter {
	public static final String DEFAULT_FILTER_PROCESSING_URI = "/oauth2/authorize";

	private static final String CLIENT_ALIAS_VARIABLE_NAME = "clientAlias";

	private final AntPathRequestMatcher authorizationRequestMatcher;

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final AuthorizationRequestUriBuilder authorizationUriBuilder;

	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();

	private final StringKeyGenerator stateGenerator = new DefaultStateGenerator();

	private AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();


	public AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository,
												AuthorizationRequestUriBuilder authorizationUriBuilder) {

		this(DEFAULT_FILTER_PROCESSING_URI, clientRegistrationRepository, authorizationUriBuilder);
	}

	public AuthorizationRequestRedirectFilter(String filterProcessingUri,
												ClientRegistrationRepository clientRegistrationRepository,
												AuthorizationRequestUriBuilder authorizationUriBuilder) {

		Assert.notNull(filterProcessingUri, "filterProcessingUri cannot be null");
		this.authorizationRequestMatcher = new AntPathRequestMatcher(
				normalizeUri(filterProcessingUri) + "/{" + CLIENT_ALIAS_VARIABLE_NAME + "}");

		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;

		Assert.notNull(authorizationUriBuilder, "authorizationUriBuilder cannot be null");
		this.authorizationUriBuilder = authorizationUriBuilder;
	}

	@Override
	public final void afterPropertiesSet() {
		Assert.notEmpty(this.clientRegistrationRepository.getRegistrations(), "clientRegistrationRepository cannot be empty");
	}

	public final void setAuthorizationRequestRepository(AuthorizationRequestRepository authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	@Override
	protected final void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.authorizationRequestMatcher.matches(request)) {
			try {
				this.obtainAuthorization(request, response);
			} catch (OAuth2Exception failed) {
				this.unsuccessfulAuthorizationRequest(request, response, failed);
			}
			return;
		}

		filterChain.doFilter(request, response);
	}

	private void obtainAuthorization(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {

		String clientAlias = this.authorizationRequestMatcher
				.extractUriTemplateVariables(request).get(CLIENT_ALIAS_VARIABLE_NAME);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.getRegistrationByClientAlias(clientAlias);
		if (clientRegistration == null) {
			throw new InvalidClientIdentifierException(clientAlias);
		}

		AuthorizationRequestAttributes authorizationRequestAttributes =
				AuthorizationRequestAttributes.authorizationCodeGrant(
						clientRegistration.getProviderDetails().getAuthorizationUri(),
						clientRegistration.getClientId(),
						clientRegistration.getRedirectUri(),
						clientRegistration.getScopes(),
						this.stateGenerator.generateKey());
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequestAttributes, request);

		URI redirectUri = null;
		try {
			redirectUri = this.authorizationUriBuilder.build(authorizationRequestAttributes);
		} catch (URISyntaxException ex) {
			logger.error("An error occurred building the Authorization Request: " + ex.getMessage(), ex);
		}
		Assert.notNull(redirectUri, "Authorization redirectUri cannot be null");

		this.authorizationRedirectStrategy.sendRedirect(request, response, redirectUri.toString());
	}

	private void unsuccessfulAuthorizationRequest(HttpServletRequest request, HttpServletResponse response,
													OAuth2Exception failed) throws IOException, ServletException {

		if (logger.isDebugEnabled()) {
			logger.debug("Authorization Request failed: " + failed.toString(), failed);
		}
		response.sendError(HttpServletResponse.SC_BAD_REQUEST, failed.getMessage());
	}

	private String normalizeUri(String uri) {
		if (!uri.startsWith("/")) {
			uri = "/" + uri;
		}
		// Check for and remove trailing '/'
		if (uri.endsWith("/")) {
			uri = uri.replaceAll("/$", "");
			uri = normalizeUri(uri);		// There may be more
		}
		return uri;
	}
}
