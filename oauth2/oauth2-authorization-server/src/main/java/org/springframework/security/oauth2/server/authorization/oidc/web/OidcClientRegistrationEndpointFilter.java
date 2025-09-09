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

package org.springframework.security.oauth2.server.authorization.oidc.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcClientRegistrationAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} that processes OpenID Connect 1.0 Dynamic Client Registration (and
 * Client Read) Requests.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @since 7.0
 * @see OidcClientRegistration
 * @see OidcClientRegistrationAuthenticationConverter
 * @see OidcClientRegistrationAuthenticationProvider
 * @see OidcClientConfigurationAuthenticationProvider
 * @see <a href=
 * "https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration">3.
 * Client Registration Endpoint</a>
 * @see <a href=
 * "https://openid.net/specs/openid-connect-registration-1_0.html#ClientConfigurationEndpoint">4.
 * Client Configuration Endpoint</a>
 */
public final class OidcClientRegistrationEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for OpenID Client Registration requests.
	 */
	private static final String DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI = "/connect/register";

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher clientRegistrationEndpointMatcher;

	private final HttpMessageConverter<OidcClientRegistration> clientRegistrationHttpMessageConverter = new OidcClientRegistrationHttpMessageConverter();

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	private AuthenticationConverter authenticationConverter = new OidcClientRegistrationAuthenticationConverter();

	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendClientRegistrationResponse;

	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;

	/**
	 * Constructs an {@code OidcClientRegistrationEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 */
	public OidcClientRegistrationEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OidcClientRegistrationEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 * @param clientRegistrationEndpointUri the endpoint {@code URI} for OpenID Client
	 * Registration requests
	 */
	public OidcClientRegistrationEndpointFilter(AuthenticationManager authenticationManager,
			String clientRegistrationEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(clientRegistrationEndpointUri, "clientRegistrationEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.clientRegistrationEndpointMatcher = new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, clientRegistrationEndpointUri),
				createClientConfigurationMatcher(clientRegistrationEndpointUri));
	}

	private static RequestMatcher createClientConfigurationMatcher(String clientRegistrationEndpointUri) {
		RequestMatcher clientConfigurationGetMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.GET, clientRegistrationEndpointUri);

		RequestMatcher clientIdMatcher = (request) -> {
			String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
			return StringUtils.hasText(clientId);
		};

		return new AndRequestMatcher(clientConfigurationGetMatcher, clientIdMatcher);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.clientRegistrationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication clientRegistrationAuthentication = this.authenticationConverter.convert(request);

			Authentication clientRegistrationAuthenticationResult = this.authenticationManager
				.authenticate(clientRegistrationAuthentication);

			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response,
					clientRegistrationAuthenticationResult);
		}
		catch (OAuth2AuthenticationException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Client registration request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
		catch (Exception ex) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
					"OpenID Connect 1.0 Client Registration Error: " + ex.getMessage(),
					"https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError");
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(error.getDescription(), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response,
					new OAuth2AuthenticationException(error));
		}
		finally {
			SecurityContextHolder.clearContext();
		}
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Client
	 * Registration Request from {@link HttpServletRequest} to an instance of
	 * {@link OidcClientRegistrationAuthenticationToken} used for authenticating the
	 * request.
	 * @param authenticationConverter an {@link AuthenticationConverter} used when
	 * attempting to extract a Client Registration Request from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OidcClientRegistrationAuthenticationToken} and returning the
	 * {@link OidcClientRegistration Client Registration Response}.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OidcClientRegistrationAuthenticationToken}
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

	private void sendClientRegistrationResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		OidcClientRegistration clientRegistration = ((OidcClientRegistrationAuthenticationToken) authentication)
			.getClientRegistration();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		if (HttpMethod.POST.name().equals(request.getMethod())) {
			httpResponse.setStatusCode(HttpStatus.CREATED);
		}
		else {
			httpResponse.setStatusCode(HttpStatus.OK);
		}
		this.clientRegistrationHttpMessageConverter.write(clientRegistration, null, httpResponse);
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException {
		OAuth2Error error = ((OAuth2AuthenticationException) authenticationException).getError();
		HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
		if (OAuth2ErrorCodes.INVALID_TOKEN.equals(error.getErrorCode())) {
			httpStatus = HttpStatus.UNAUTHORIZED;
		}
		else if (OAuth2ErrorCodes.INSUFFICIENT_SCOPE.equals(error.getErrorCode())) {
			httpStatus = HttpStatus.FORBIDDEN;
		}
		else if (OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())) {
			httpStatus = HttpStatus.UNAUTHORIZED;
		}
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(httpStatus);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

}
