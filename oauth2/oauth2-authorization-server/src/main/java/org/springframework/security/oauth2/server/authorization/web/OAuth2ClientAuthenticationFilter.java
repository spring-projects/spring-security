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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.PublicClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.X509ClientCertificateAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.JwtClientAssertionAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.PublicClientAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.X509ClientCertificateAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} that processes an authentication request for an OAuth 2.0 Client.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @since 7.0
 * @see AuthenticationManager
 * @see JwtClientAssertionAuthenticationConverter
 * @see JwtClientAssertionAuthenticationProvider
 * @see X509ClientCertificateAuthenticationConverter
 * @see X509ClientCertificateAuthenticationProvider
 * @see ClientSecretBasicAuthenticationConverter
 * @see ClientSecretPostAuthenticationConverter
 * @see ClientSecretAuthenticationProvider
 * @see PublicClientAuthenticationConverter
 * @see PublicClientAuthenticationProvider
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-2.3">Section 2.3 Client
 * Authentication</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1">Section 3.2.1 Token
 * Endpoint Client Authentication</a>
 */
public final class OAuth2ClientAuthenticationFilter extends OncePerRequestFilter {

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher requestMatcher;

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private AuthenticationConverter authenticationConverter;

	private AuthenticationSuccessHandler authenticationSuccessHandler = this::onAuthenticationSuccess;

	private AuthenticationFailureHandler authenticationFailureHandler = this::onAuthenticationFailure;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationFilter} using the provided
	 * parameters.
	 * @param authenticationManager the {@link AuthenticationManager} used for
	 * authenticating the client
	 * @param requestMatcher the {@link RequestMatcher} used for matching against the
	 * {@code HttpServletRequest}
	 */
	public OAuth2ClientAuthenticationFilter(AuthenticationManager authenticationManager,
			RequestMatcher requestMatcher) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.authenticationManager = authenticationManager;
		this.requestMatcher = requestMatcher;
		// @formatter:off
		this.authenticationConverter = new DelegatingAuthenticationConverter(
				Arrays.asList(
						new JwtClientAssertionAuthenticationConverter(),
						new ClientSecretBasicAuthenticationConverter(),
						new ClientSecretPostAuthenticationConverter(),
						new PublicClientAuthenticationConverter(),
						new X509ClientCertificateAuthenticationConverter()));
		// @formatter:on
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication authenticationRequest = this.authenticationConverter.convert(request);
			if (authenticationRequest instanceof AbstractAuthenticationToken authenticationToken) {
				authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
			}
			if (authenticationRequest != null) {
				validateClientIdentifier(authenticationRequest);
				Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);
				this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult);
			}
			filterChain.doFilter(request, response);

		}
		catch (OAuth2AuthenticationException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Client authentication failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract client
	 * credentials from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2ClientAuthenticationToken} used for authenticating the client.
	 * @param authenticationConverter the {@link AuthenticationConverter} used when
	 * attempting to extract client credentials from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling a successful client
	 * authentication and associating the {@link OAuth2ClientAuthenticationToken} to the
	 * {@link SecurityContext}.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling a successful client authentication
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling a failed client
	 * authentication and returning the {@link OAuth2Error Error Response}.
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used
	 * for handling a failed client authentication
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
	}

	private void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {

		SecurityContextHolder.clearContext();

		// TODO
		// The authorization server MAY return an HTTP 401 (Unauthorized) status code
		// to indicate which HTTP authentication schemes are supported.
		// If the client attempted to authenticate via the "Authorization" request header
		// field,
		// the authorization server MUST respond with an HTTP 401 (Unauthorized) status
		// code and
		// include the "WWW-Authenticate" response header field
		// matching the authentication scheme used by the client.

		OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		if (OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())) {
			httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
		}
		else {
			httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		}
		// We don't want to reveal too much information to the caller so just return the
		// error code
		OAuth2Error errorResponse = new OAuth2Error(error.getErrorCode());
		this.errorHttpResponseConverter.write(errorResponse, null, httpResponse);
	}

	private static void validateClientIdentifier(Authentication authentication) {
		if (!(authentication instanceof OAuth2ClientAuthenticationToken)) {
			return;
		}

		// As per spec, in Appendix A.1.
		// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07#appendix-A.1
		// The syntax for client_id is *VSCHAR (%x20-7E):
		// -> Hex 20 -> ASCII 32 -> space
		// -> Hex 7E -> ASCII 126 -> tilde

		OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;
		String clientId = (String) clientAuthentication.getPrincipal();
		for (int i = 0; i < clientId.length(); i++) {
			char charAt = clientId.charAt(i);
			if (!(charAt >= 32 && charAt <= 126)) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
			}
		}
	}

}
