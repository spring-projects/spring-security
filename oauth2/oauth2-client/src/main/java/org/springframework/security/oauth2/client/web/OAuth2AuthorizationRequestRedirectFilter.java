/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.client.web;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
 * at the {@code URI} {@code /oauth2/authorization/{registrationId}}
 * using the default {@link OAuth2AuthorizationRequestResolver}.
 * The {@code URI} template variable {@code {registrationId}} represents the
 * {@link ClientRegistration#getRegistrationId() registration identifier} of the client
 * that is used for initiating the OAuth 2.0 Authorization Request.
 *
 * <p>
 * The default base {@code URI} {@code /oauth2/authorization} may be overridden
 * via the constructor {@link #OAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository, String)},
 * or alternatively, an {@code OAuth2AuthorizationRequestResolver} may be provided to the constructor
 * {@link #OAuth2AuthorizationRequestRedirectFilter(OAuth2AuthorizationRequestResolver)}
 * to override the resolving of authorization requests.

 * @author Joe Grandja
 * @author Rob Winch
 * @since 5.0
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationRequestResolver
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
	private final ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();
	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
	private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
		new HttpSessionOAuth2AuthorizationRequestRepository();
	private RequestCache requestCache = new HttpSessionRequestCache();

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
	public OAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository,
													String authorizationRequestBaseUri) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
		this.authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
				clientRegistrationRepository, authorizationRequestBaseUri);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
	 *
	 * @since 5.1
	 * @param authorizationRequestResolver the resolver used for resolving authorization requests
	 */
	public OAuth2AuthorizationRequestRedirectFilter(OAuth2AuthorizationRequestResolver authorizationRequestResolver) {
		Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
		this.authorizationRequestResolver = authorizationRequestResolver;
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

		try {
			OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request);
			if (authorizationRequest != null) {
				this.sendRedirectForAuthorization(request, response, authorizationRequest);
				return;
			}
		} catch (Exception failed) {
			this.unsuccessfulRedirectForAuthorization(request, response, failed);
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
					OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request, authzEx.getClientRegistrationId());
					if (authorizationRequest == null) {
						throw authzEx;
					}
					this.sendRedirectForAuthorization(request, response, authorizationRequest);
					this.requestCache.saveRequest(request, response);
				} catch (Exception failed) {
					this.unsuccessfulRedirectForAuthorization(request, response, failed);
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

	private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
												OAuth2AuthorizationRequest authorizationRequest) throws IOException, ServletException {

		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
			this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
		}
		this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getAuthorizationRequestUri());
	}

	private void unsuccessfulRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
														Exception failed) throws IOException, ServletException {

		if (logger.isErrorEnabled()) {
			logger.error("Authorization Request failed: " + failed.toString(), failed);
		}
		response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
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
