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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

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
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceAuthorizationConsentAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceVerificationAuthenticationConverter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} for the OAuth 2.0 Device Authorization Grant, which handles the
 * processing of the Device Verification Request (submission of the user code) and the
 * Device Authorization Consent.
 *
 * @author Steve Riesenberg
 * @since 7.0
 * @see AuthenticationManager
 * @see OAuth2DeviceVerificationAuthenticationConverter
 * @see OAuth2DeviceVerificationAuthenticationProvider
 * @see OAuth2DeviceAuthorizationConsentAuthenticationConverter
 * @see OAuth2DeviceAuthorizationConsentAuthenticationProvider
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628">OAuth 2.0
 * Device Authorization Grant</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc8628#section-3.3">Section 3.3 User
 * Interaction</a>
 */
public final class OAuth2DeviceVerificationEndpointFilter extends OncePerRequestFilter {

	static final String DEFAULT_DEVICE_VERIFICATION_ENDPOINT_URI = "/oauth2/device_verification";

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher deviceVerificationEndpointMatcher;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private AuthenticationConverter authenticationConverter;

	private AuthenticationSuccessHandler authenticationSuccessHandler = new SimpleUrlAuthenticationSuccessHandler(
			"/?success");

	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;

	private String consentPage;

	/**
	 * Constructs an {@code OAuth2DeviceVerificationEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2DeviceVerificationEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_DEVICE_VERIFICATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2DeviceVerificationEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 * @param deviceVerificationEndpointUri the endpoint {@code URI} for device
	 * verification requests
	 */
	public OAuth2DeviceVerificationEndpointFilter(AuthenticationManager authenticationManager,
			String deviceVerificationEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(deviceVerificationEndpointUri, "deviceVerificationEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.deviceVerificationEndpointMatcher = createDefaultRequestMatcher(deviceVerificationEndpointUri);
		// @formatter:off
		this.authenticationConverter = new DelegatingAuthenticationConverter(
				Arrays.asList(
						new OAuth2DeviceVerificationAuthenticationConverter(),
						new OAuth2DeviceAuthorizationConsentAuthenticationConverter()));
		// @formatter:on
	}

	private RequestMatcher createDefaultRequestMatcher(String deviceVerificationEndpointUri) {
		RequestMatcher verificationRequestGetMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.GET, deviceVerificationEndpointUri);
		RequestMatcher verificationRequestPostMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, deviceVerificationEndpointUri);
		RequestMatcher userCodeParameterMatcher = (
				request) -> request.getParameter(OAuth2ParameterNames.USER_CODE) != null;

		return new AndRequestMatcher(
				new OrRequestMatcher(verificationRequestGetMatcher, verificationRequestPostMatcher),
				userCodeParameterMatcher);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.deviceVerificationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication authentication = this.authenticationConverter.convert(request);
			if (authentication instanceof AbstractAuthenticationToken authenticationToken) {
				authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
			}

			Authentication authenticationResult = this.authenticationManager.authenticate(authentication);
			if (!authenticationResult.isAuthenticated()) {
				// If the Principal (Resource Owner) is not authenticated then pass
				// through the chain
				// with the expectation that the authentication process will commence via
				// AuthenticationEntryPoint
				filterChain.doFilter(request, response);
				return;
			}

			if (authenticationResult instanceof OAuth2DeviceAuthorizationConsentAuthenticationToken) {
				if (this.logger.isTraceEnabled()) {
					this.logger.trace("Device authorization consent is required");
				}
				sendAuthorizationConsent(request, response, authenticationResult);
				return;
			}

			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult);
		}
		catch (OAuth2AuthenticationException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Device verification request failed: %s", ex.getError()), ex);
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
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Device
	 * Verification Request (or Device Authorization Consent) from
	 * {@link HttpServletRequest} to an instance of
	 * {@link OAuth2DeviceVerificationAuthenticationToken} or
	 * {@link OAuth2DeviceAuthorizationConsentAuthenticationToken} used for authenticating
	 * the request.
	 * @param authenticationConverter the {@link AuthenticationConverter} used when
	 * attempting to extract a Device Verification Request (or Device Authorization
	 * Consent) from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2DeviceVerificationAuthenticationToken} and returning the response.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OAuth2DeviceVerificationAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthenticationException} and returning the {@link OAuth2Error Error
	 * Response}.
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used
	 * for handling an {@link OAuth2AuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
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
			Authentication authentication) throws IOException {

		OAuth2DeviceAuthorizationConsentAuthenticationToken authorizationConsentAuthentication = (OAuth2DeviceAuthorizationConsentAuthenticationToken) authentication;

		String clientId = authorizationConsentAuthentication.getClientId();
		Authentication principal = (Authentication) authorizationConsentAuthentication.getPrincipal();
		Set<String> requestedScopes = authorizationConsentAuthentication.getRequestedScopes();
		Set<String> authorizedScopes = authorizationConsentAuthentication.getScopes();
		String state = authorizationConsentAuthentication.getState();
		String userCode = authorizationConsentAuthentication.getUserCode();

		if (hasConsentUri()) {
			String redirectUri = UriComponentsBuilder.fromUriString(resolveConsentUri(request))
				.queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", requestedScopes))
				.queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
				.queryParam(OAuth2ParameterNames.STATE, state)
				.queryParam(OAuth2ParameterNames.USER_CODE, userCode)
				.toUriString();
			this.redirectStrategy.sendRedirect(request, response, redirectUri);
		}
		else {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Displaying generated consent screen");
			}
			Map<String, String> additionalParameters = new HashMap<>();
			additionalParameters.put(OAuth2ParameterNames.USER_CODE, userCode);
			DefaultConsentPage.displayConsent(request, response, clientId, principal, requestedScopes, authorizedScopes,
					state, additionalParameters);
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

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException {

		OAuth2Error error = ((OAuth2AuthenticationException) authenticationException).getError();
		response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
	}

}
