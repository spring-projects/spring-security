/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.function.Consumer;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationConsentAuthenticationConverter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * A {@code Filter} for the OAuth 2.0 Authorization Code Grant, which handles the
 * processing of the OAuth 2.0 Authorization Request and Consent.
 *
 * @author Joe Grandja
 * @author Paurav Munshi
 * @author Daniel Garnier-Moiroux
 * @author Anoop Garlapati
 * @author Dmitriy Dubson
 * @since 7.0
 * @see AuthenticationManager
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see OAuth2AuthorizationConsentAuthenticationProvider
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">Section 4.1 Authorization
 * Code Grant</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">Section 4.1.1
 * Authorization Request</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2">Section 4.1.2
 * Authorization Response</a>
 */
public final class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for authorization requests.
	 */
	private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher authorizationEndpointMatcher;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private AuthenticationConverter authenticationConverter;

	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendAuthorizationResponse;

	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;

	private SessionAuthenticationStrategy sessionAuthenticationStrategy = (authentication, request, response) -> {
	};

	private String consentPage;

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 * @param authorizationEndpointUri the endpoint {@code URI} for authorization requests
	 */
	public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager,
			String authorizationEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(authorizationEndpointUri, "authorizationEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.authorizationEndpointMatcher = createDefaultRequestMatcher(authorizationEndpointUri);
		// @formatter:off
		this.authenticationConverter = new DelegatingAuthenticationConverter(
				Arrays.asList(
						new OAuth2AuthorizationCodeRequestAuthenticationConverter(),
						new OAuth2AuthorizationConsentAuthenticationConverter()));
		// @formatter:on
	}

	private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
		RequestMatcher authorizationRequestGetMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.GET, authorizationEndpointUri);
		RequestMatcher authorizationRequestPostMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, authorizationEndpointUri);
		RequestMatcher authorizationConsentMatcher = createAuthorizationConsentMatcher(authorizationEndpointUri);
		RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(authorizationRequestGetMatcher,
				new AndRequestMatcher(authorizationRequestPostMatcher,
						new NegatedRequestMatcher(authorizationConsentMatcher)));
		return new OrRequestMatcher(authorizationRequestMatcher, authorizationConsentMatcher);
	}

	private static RequestMatcher createAuthorizationConsentMatcher(String authorizationEndpointUri) {
		final RequestMatcher authorizationConsentPostMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, authorizationEndpointUri);
		return (request) -> authorizationConsentPostMatcher.matches(request)
				&& request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) == null
				&& request.getParameter(OAuth2ParameterNames.REQUEST_URI) == null
				&& request.getParameter(OAuth2ParameterNames.REDIRECT_URI) == null
				&& request.getParameter(PkceParameterNames.CODE_CHALLENGE) == null
				&& request.getParameter(PkceParameterNames.CODE_CHALLENGE_METHOD) == null;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.authorizationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			// Get the pre-validated authorization code request (if available),
			// which was set by OAuth2AuthorizationCodeRequestValidatingFilter
			Authentication authentication = (Authentication) request
				.getAttribute(OAuth2AuthorizationCodeRequestAuthenticationToken.class.getName());
			if (authentication == null) {
				authentication = this.authenticationConverter.convert(request);
				if (authentication instanceof AbstractAuthenticationToken authenticationToken) {
					authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
				}
			}
			Authentication authenticationResult = this.authenticationManager.authenticate(authentication);

			if (authenticationResult instanceof OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthenticationToken) {
				if (this.logger.isTraceEnabled()) {
					this.logger.trace("Authorization consent is required");
				}
				sendAuthorizationConsent(request, response,
						(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication,
						authorizationConsentAuthenticationToken);
				return;
			}

			this.sessionAuthenticationStrategy.onAuthentication(authenticationResult, request, response);

			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult);

		}
		catch (OAuth2AuthenticationException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Authorization request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	/**
	 * Sets the {@link AuthenticationDetailsSource} used for building an authentication
	 * details instance from {@link HttpServletRequest}.
	 * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} used for
	 * building an authentication details instance from {@link HttpServletRequest}
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an
	 * Authorization Request (or Consent) from {@link HttpServletRequest} to an instance
	 * of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} or
	 * {@link OAuth2AuthorizationConsentAuthenticationToken} used for authenticating the
	 * request.
	 * @param authenticationConverter the {@link AuthenticationConverter} used when
	 * attempting to extract an Authorization Request (or Consent) from
	 * {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken} and returning the
	 * {@link OAuth2AuthorizationResponse Authorization Response}.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationException} and returning the
	 * {@link OAuth2Error Error Response}.
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used
	 * for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	/**
	 * Sets the {@link SessionAuthenticationStrategy} used for handling an
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken} before calling the
	 * {@link AuthenticationSuccessHandler}. If OpenID Connect is enabled, the default
	 * implementation tracks OpenID Connect sessions using a {@link SessionRegistry}.
	 * @param sessionAuthenticationStrategy the {@link SessionAuthenticationStrategy} used
	 * for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 */
	public void setSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		Assert.notNull(sessionAuthenticationStrategy, "sessionAuthenticationStrategy cannot be null");
		this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
	}

	/**
	 * Specify the URI to redirect Resource Owners to if consent is required. A default
	 * consent page will be generated when this attribute is not specified.
	 * @param consentPage the URI of the custom consent page to redirect to if consent is
	 * required (e.g. "/oauth2/consent")
	 */
	public void setConsentPage(String consentPage) {
		this.consentPage = consentPage;
	}

	private void sendAuthorizationConsent(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication) throws IOException {

		String clientId = authorizationConsentAuthentication.getClientId();
		Authentication principal = (Authentication) authorizationConsentAuthentication.getPrincipal();
		Set<String> authorizedScopes = authorizationConsentAuthentication.getScopes();
		String state = authorizationConsentAuthentication.getState();

		Set<String> requestedScopes;
		String requestUri = (String) authorizationCodeRequestAuthentication.getAdditionalParameters()
			.get(OAuth2ParameterNames.REQUEST_URI);
		if (StringUtils.hasText(requestUri)) {
			requestedScopes = (Set<String>) authorizationConsentAuthentication.getAdditionalParameters()
				.get(OAuth2ParameterNames.SCOPE);
		}
		else {
			requestedScopes = authorizationCodeRequestAuthentication.getScopes();
		}

		if (hasConsentUri()) {
			String redirectUri = UriComponentsBuilder.fromUriString(resolveConsentUri(request))
				.queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", requestedScopes))
				.queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
				.queryParam(OAuth2ParameterNames.STATE, state)
				.toUriString();
			this.redirectStrategy.sendRedirect(request, response, redirectUri);
		}
		else {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Displaying generated consent screen");
			}
			DefaultConsentPage.displayConsent(request, response, clientId, principal, requestedScopes, authorizedScopes,
					state, Collections.emptyMap());
		}
	}

	private boolean hasConsentUri() {
		return StringUtils.hasText(this.consentPage);
	}

	private String resolveConsentUri(HttpServletRequest request) {
		if (UrlUtils.isAbsoluteUrl(this.consentPage)) {
			return this.consentPage;
		}
		RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
		urlBuilder.setScheme(request.getScheme());
		urlBuilder.setServerName(request.getServerName());
		urlBuilder.setPort(request.getServerPort());
		urlBuilder.setContextPath(request.getContextPath());
		urlBuilder.setPathInfo(this.consentPage);
		return urlBuilder.getUrl();
	}

	private void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
		UriComponentsBuilder uriBuilder = UriComponentsBuilder
			.fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
			.queryParam(OAuth2ParameterNames.CODE,
					authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());
		if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE,
					UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
		}
		// build(true) -> Components are explicitly encoded
		String redirectUri = uriBuilder.build(true).toUriString();
		this.redirectStrategy.sendRedirect(request, response, redirectUri);
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {

		OAuth2AuthorizationCodeRequestAuthenticationException authorizationCodeRequestAuthenticationException = (OAuth2AuthorizationCodeRequestAuthenticationException) exception;
		OAuth2Error error = authorizationCodeRequestAuthenticationException.getError();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authorizationCodeRequestAuthenticationException
			.getAuthorizationCodeRequestAuthentication();

		if (authorizationCodeRequestAuthentication == null
				|| !StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
			return;
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Redirecting to client with error");
		}

		UriComponentsBuilder uriBuilder = UriComponentsBuilder
			.fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
			.queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
		if (StringUtils.hasText(error.getDescription())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION,
					UriUtils.encode(error.getDescription(), StandardCharsets.UTF_8));
		}
		if (StringUtils.hasText(error.getUri())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI,
					UriUtils.encode(error.getUri(), StandardCharsets.UTF_8));
		}
		if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE,
					UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
		}
		// build(true) -> Components are explicitly encoded
		String redirectUri = uriBuilder.build(true).toUriString();
		this.redirectStrategy.sendRedirect(request, response, redirectUri);
	}

	Filter createAuthorizationCodeRequestValidatingFilter(RegisteredClientRepository registeredClientRepository,
			Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator) {
		return new OAuth2AuthorizationCodeRequestValidatingFilter(registeredClientRepository, authenticationValidator);
	}

	/**
	 * A {@code Filter} that is applied before {@code OAuth2AuthorizationEndpointFilter}
	 * and handles the pre-validation of an OAuth 2.0 Authorization Code Request.
	 */
	private final class OAuth2AuthorizationCodeRequestValidatingFilter extends OncePerRequestFilter {

		private final RegisteredClientRepository registeredClientRepository;

		private final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator;

		private final Field setValidatedField;

		private OAuth2AuthorizationCodeRequestValidatingFilter(RegisteredClientRepository registeredClientRepository,
				Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator) {
			Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
			Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
			this.registeredClientRepository = registeredClientRepository;
			this.authenticationValidator = authenticationValidator;
			this.setValidatedField = ReflectionUtils.findField(OAuth2AuthorizationCodeRequestAuthenticationToken.class,
					"validated");
			ReflectionUtils.makeAccessible(this.setValidatedField);
		}

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
				FilterChain filterChain) throws ServletException, IOException {

			if (!OAuth2AuthorizationEndpointFilter.this.authorizationEndpointMatcher.matches(request)) {
				filterChain.doFilter(request, response);
				return;
			}

			try {
				Authentication authentication = OAuth2AuthorizationEndpointFilter.this.authenticationConverter
					.convert(request);
				if (!(authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication)) {
					filterChain.doFilter(request, response);
					return;
				}

				String requestUri = (String) authorizationCodeRequestAuthentication.getAdditionalParameters()
					.get(OAuth2ParameterNames.REQUEST_URI);
				if (StringUtils.hasText(requestUri)) {
					filterChain.doFilter(request, response);
					return;
				}

				authorizationCodeRequestAuthentication.setDetails(
						OAuth2AuthorizationEndpointFilter.this.authenticationDetailsSource.buildDetails(request));

				RegisteredClient registeredClient = this.registeredClientRepository
					.findByClientId(authorizationCodeRequestAuthentication.getClientId());
				if (registeredClient == null) {
					String redirectUri = null; // Prevent redirect
					OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
							authorizationCodeRequestAuthentication.getAuthorizationUri(),
							authorizationCodeRequestAuthentication.getClientId(),
							(Authentication) authorizationCodeRequestAuthentication.getPrincipal(), redirectUri,
							authorizationCodeRequestAuthentication.getState(),
							authorizationCodeRequestAuthentication.getScopes(),
							authorizationCodeRequestAuthentication.getAdditionalParameters());

					OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
							"OAuth 2.0 Parameter: " + OAuth2ParameterNames.CLIENT_ID,
							"https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1");
					throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,
							authorizationCodeRequestAuthenticationResult);
				}

				OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext = OAuth2AuthorizationCodeRequestAuthenticationContext
					.with(authorizationCodeRequestAuthentication)
					.registeredClient(registeredClient)
					.build();

				this.authenticationValidator.accept(authenticationContext);

				ReflectionUtils.setField(this.setValidatedField, authorizationCodeRequestAuthentication, true);

				// Set the validated authorization code request as a request
				// attribute
				// to be used upstream by OAuth2AuthorizationEndpointFilter
				request.setAttribute(OAuth2AuthorizationCodeRequestAuthenticationToken.class.getName(),
						authorizationCodeRequestAuthentication);

				filterChain.doFilter(request, response);
			}
			catch (OAuth2AuthenticationException ex) {
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(LogMessage.format("Authorization request failed: %s", ex.getError()), ex);
				}
				OAuth2AuthorizationEndpointFilter.this.authenticationFailureHandler.onAuthenticationFailure(request,
						response, ex);
			}
			finally {
				request.removeAttribute(OAuth2AuthorizationCodeRequestAuthenticationToken.class.getName());
			}
		}

	}

}
