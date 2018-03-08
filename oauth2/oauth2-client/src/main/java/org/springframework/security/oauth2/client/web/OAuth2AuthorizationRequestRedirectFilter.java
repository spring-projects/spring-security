/*
 * Copyright 2002-2018 the original author or authors.
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
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
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
 * This {@code Filter} initiates the authorization code grant or implicit grant flow
 * by redirecting the End-User's user-agent to the Authorization Server's Authorization Endpoint.
 *
 * <p>
 * It builds the OAuth 2.0 Authorization Request,
 * which is used as the redirect {@code URI} to the Authorization Endpoint.
 * The redirect {@code URI} will include the client identifier, requested scope(s), state,
 * response type, and a redirection URI which the authorization server will send the user-agent back to
 * once access is granted (or denied) by the End-User (Resource Owner).
 *
 * <p>
 * By default, this {@code Filter} responds to authorization requests
 * at the {@code URI} {@code /oauth2/authorization/{registrationId}}.
 * The {@code URI} template variable {@code {registrationId}} represents the
 * {@link ClientRegistration#getRegistrationId() registration identifier} of the client
 * that is used for initiating the OAuth 2.0 Authorization Request.
 *
 * <p>
 * <b>NOTE:</b> The default base {@code URI} {@code /oauth2/authorization} may be overridden
 * via it's constructor {@link #OAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository, String)}.

 * @author Joe Grandja
 * @author Rob Winch
 * @since 5.0
 * @see OAuth2AuthorizationRequest
 * @see AuthorizationRequestRepository
 * @see ClientRegistration
 * @see ClientRegistrationRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request (Authorization Code)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2">Section 4.2 Implicit Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2.1">Section 4.2.1 Authorization Request (Implicit)</a>
 */
public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {
	/**
	 * The default base {@code URI} used for authorization requests.
	 */
	public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
	private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
	private static final String AUTHORIZATION_REQUIRED_EXCEPTION_ATTR_NAME =
			ClientAuthorizationRequiredException.class.getName() + ".AUTHORIZATION_REQUIRED_EXCEPTION";
	private final AntPathRequestMatcher authorizationRequestMatcher;
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizationRequestUriBuilder authorizationRequestUriBuilder = new OAuth2AuthorizationRequestUriBuilder();
	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
	private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
		new HttpSessionOAuth2AuthorizationRequestRepository();
	private RequestCache requestCache = new HttpSessionRequestCache();
	private final ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

	/**
	 * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 */
	public OAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository) {
		this(clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizationRequestBaseUri the base {@code URI} used for authorization requests
	 */
	public OAuth2AuthorizationRequestRedirectFilter(
		ClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {

		Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.authorizationRequestMatcher = new AntPathRequestMatcher(
			authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	/**
	 * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
	 *
	 * @param authorizationRequestRepository the repository used for storing {@link OAuth2AuthorizationRequest}'s
	 */
	public final void setAuthorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	/**
	 * Sets the {@link RequestCache} used for storing the current request
	 * before redirecting the OAuth 2.0 Authorization Request.
	 *
	 * @param requestCache the cache used for storing the current request
	 */
	public final void setRequestCache(RequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
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

		try {
			filterChain.doFilter(request, response);
		} catch (IOException ex) {
			throw ex;
		} catch (Exception ex) {
			// Check to see if we need to handle ClientAuthorizationRequiredException
			Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
			ClientAuthorizationRequiredException authzEx = (ClientAuthorizationRequiredException) this.throwableAnalyzer
				.getFirstThrowableOfType(ClientAuthorizationRequiredException.class, causeChain);
			if (authzEx != null) {
				try {
					request.setAttribute(AUTHORIZATION_REQUIRED_EXCEPTION_ATTR_NAME, authzEx);
					this.sendRedirectForAuthorization(request, response, authzEx.getClientRegistrationId());
					this.requestCache.saveRequest(request, response);
				} catch (Exception failed) {
					this.unsuccessfulRedirectForAuthorization(request, response, failed);
				} finally {
					request.removeAttribute(AUTHORIZATION_REQUIRED_EXCEPTION_ATTR_NAME);
				}
				return;
			}

			if (ex instanceof ServletException) {
				throw (ServletException) ex;
			} else if (ex instanceof RuntimeException) {
				throw (RuntimeException) ex;
			} else {
				throw new RuntimeException(ex);
			}
		}
	}

	private boolean shouldRequestAuthorization(HttpServletRequest request, HttpServletResponse response) {
		return this.authorizationRequestMatcher.matches(request);
	}

	private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response)
		throws IOException, ServletException {

		String registrationId = this.authorizationRequestMatcher
			.extractUriTemplateVariables(request).get(REGISTRATION_ID_URI_VARIABLE_NAME);
		this.sendRedirectForAuthorization(request, response, registrationId);
	}

	private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
												String registrationId) throws IOException, ServletException {

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
		}
		this.sendRedirectForAuthorization(request, response, clientRegistration);
	}

	private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
												ClientRegistration clientRegistration) throws IOException, ServletException {

		String redirectUriStr = this.expandRedirectUri(request, clientRegistration);

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());

		OAuth2AuthorizationRequest.Builder builder;
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			builder = OAuth2AuthorizationRequest.authorizationCode();
		} else if (AuthorizationGrantType.IMPLICIT.equals(clientRegistration.getAuthorizationGrantType())) {
			builder = OAuth2AuthorizationRequest.implicit();
		} else {
			throw new IllegalArgumentException("Invalid Authorization Grant Type for Client Registration (" +
				clientRegistration.getRegistrationId() + "): " + clientRegistration.getAuthorizationGrantType());
		}
		OAuth2AuthorizationRequest authorizationRequest = builder
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
		int port = request.getServerPort();
		if (("http".equals(request.getScheme()) && port == 80) || ("https".equals(request.getScheme()) && port == 443)) {
			port = -1;		// Removes the port in UriComponentsBuilder
		}

		// Supported URI variables -> baseUrl, action, registrationId
		// Used in -> CommonOAuth2Provider.DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}"
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		String baseUrl = UriComponentsBuilder.newInstance()
			.scheme(request.getScheme())
			.host(request.getServerName())
			.port(port)
			.path(request.getContextPath())
			.build()
			.toUriString();
		uriVariables.put("baseUrl", baseUrl);

		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			String loginAction = "login";
			String authorizeAction = "authorize";
			String actionParameter = "action";
			String action;
			if (request.getAttribute(AUTHORIZATION_REQUIRED_EXCEPTION_ATTR_NAME) != null) {
				action = authorizeAction;
			} else if (request.getParameter(actionParameter) == null) {
				action = loginAction;
			} else {
				String actionValue = request.getParameter(actionParameter);
				if (loginAction.equalsIgnoreCase(actionValue)) {
					action = loginAction;
				} else {
					action = authorizeAction;
				}
			}
			uriVariables.put("action", action);
		}

		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
			.buildAndExpand(uriVariables)
			.toUriString();
	}

	private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {
		protected void initExtractorMap() {
			super.initExtractorMap();
			registerExtractor(ServletException.class, throwable -> {
				ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
				return ((ServletException) throwable).getRootCause();
			});
		}
	}
}
