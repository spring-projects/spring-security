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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2Parameter;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * An implementation of an {@link AbstractAuthenticationProcessingFilter} that handles
 * the processing of an <i>OAuth 2.0 Authorization Response</i> for the authorization code grant flow.
 *
 * <p>
 * This <code>Filter</code> processes the <i>Authorization Response</i> as follows:
 *
 * <ul>
 * <li>
 *	Assuming the resource owner (end-user) has granted access to the client, the authorization server will append the
 *	{@link OAuth2Parameter#CODE} and {@link OAuth2Parameter#STATE} (if provided in the <i>Authorization Request</i>) parameters
 *	to the {@link OAuth2Parameter#REDIRECT_URI} (provided in the <i>Authorization Request</i>)
 *	and redirect the end-user's user-agent back to this <code>Filter</code> (the client).
 * </li>
 * <li>
 *  This <code>Filter</code> will then create an {@link AuthorizationCodeAuthenticationToken} with
 *  the {@link OAuth2Parameter#CODE} received in the previous step and delegate it to
 *  {@link AuthorizationCodeAuthenticationProvider#authenticate(Authentication)} (indirectly via {@link AuthenticationManager}).
 * </li>
 * </ul>
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractAuthenticationProcessingFilter
 * @see AuthorizationCodeAuthenticationToken
 * @see AuthorizationCodeAuthenticationProvider
 * @see AuthorizationResponse
 * @see AuthorizationRequest
 * @see AuthorizationRequestRepository
 * @see AuthorizationRequestRedirectFilter
 * @see ClientRegistrationRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public class AuthorizationCodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	public static final String DEFAULT_AUTHORIZATION_RESPONSE_BASE_URI = "/oauth2/authorize/code";
	private static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";
	private AuthorizationResponseMatcher authorizationResponseMatcher;
	private ClientRegistrationRepository clientRegistrationRepository;
	private AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();

	public AuthorizationCodeAuthenticationFilter() {
		this(DEFAULT_AUTHORIZATION_RESPONSE_BASE_URI);
	}

	public AuthorizationCodeAuthenticationFilter(String authorizationResponseBaseUri) {
		super(new AuthorizationResponseMatcher(authorizationResponseBaseUri));
		this.authorizationResponseMatcher = new AuthorizationResponseMatcher(authorizationResponseBaseUri);
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(this.clientRegistrationRepository, "clientRegistrationRepository cannot be null");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.loadAuthorizationRequest(request);
		if (authorizationRequest == null) {
			OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		this.authorizationRequestRepository.removeAuthorizationRequest(request);

		AuthorizationResponse authorizationResponse = this.authorizationResponseMatcher.convert(request);

		String registrationId = (String)authorizationRequest.getAdditionalParameters().get(OAuth2Parameter.REGISTRATION_ID);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

		// The clientRegistration.redirectUri may contain Uri template variables, whether it's configured by
		// the user or configured by default. In these cases, the redirectUri will be expanded and ultimately changed
		// (by AuthorizationRequestRedirectFilter) before setting it in the authorization request.
		// The resulting redirectUri used for the authorization request and saved within the AuthorizationRequestRepository
		// MUST BE the same one used to complete the authorization code flow.
		// Therefore, we'll create a copy of the clientRegistration and override the redirectUri
		// with the one contained in authorizationRequest.
		clientRegistration = new ClientRegistration.Builder(clientRegistration)
			.redirectUri(authorizationRequest.getRedirectUri())
			.build();

		AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = new AuthorizationCodeAuthenticationToken(
				clientRegistration, authorizationRequest, authorizationResponse);
		authorizationCodeAuthentication.setDetails(this.authenticationDetailsSource.buildDetails(request));

		OAuth2ClientAuthenticationToken clientAuthentication =
			(OAuth2ClientAuthenticationToken)this.getAuthenticationManager().authenticate(authorizationCodeAuthentication);

		return this.getAuthenticationManager().authenticate(clientAuthentication);
	}

	public final RequestMatcher getAuthorizationResponseMatcher() {
		return this.authorizationResponseMatcher;
	}

	public final void setAuthorizationResponseBaseUri(String authorizationResponseBaseUri) {
		Assert.hasText(authorizationResponseBaseUri, "authorizationResponseBaseUri cannot be empty");
		this.authorizationResponseMatcher = new AuthorizationResponseMatcher(authorizationResponseBaseUri);
		this.setRequiresAuthenticationRequestMatcher(this.authorizationResponseMatcher);
	}

	public final void setClientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	public final void setAuthorizationRequestRepository(AuthorizationRequestRepository authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	private static class AuthorizationResponseMatcher implements RequestMatcher {
		private final String baseUri;

		private AuthorizationResponseMatcher(String baseUri) {
			Assert.hasText(baseUri, "baseUri cannot be empty");
			this.baseUri = baseUri;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return request.getRequestURI().startsWith(this.baseUri) &&
				(this.successResponse(request) || this.errorResponse(request));
		}

		private boolean successResponse(HttpServletRequest request) {
			return StringUtils.hasText(request.getParameter(OAuth2Parameter.CODE)) &&
				StringUtils.hasText(request.getParameter(OAuth2Parameter.STATE));
		}

		private boolean errorResponse(HttpServletRequest request) {
			return StringUtils.hasText(request.getParameter(OAuth2Parameter.ERROR)) &&
				StringUtils.hasText(request.getParameter(OAuth2Parameter.STATE));
		}

		private AuthorizationResponse convert(HttpServletRequest request) {
			if (!this.matches(request)) {
				return null;
			}

			String code = request.getParameter(OAuth2Parameter.CODE);
			String errorCode = request.getParameter(OAuth2Parameter.ERROR);
			String state = request.getParameter(OAuth2Parameter.STATE);
			String redirectUri = request.getRequestURL().toString();

			if (StringUtils.hasText(code)) {
				return AuthorizationResponse.success(code)
					.redirectUri(redirectUri)
					.state(state)
					.build();
			} else {
				String errorDescription = request.getParameter(OAuth2Parameter.ERROR_DESCRIPTION);
				String errorUri = request.getParameter(OAuth2Parameter.ERROR_URI);
				return AuthorizationResponse.error(errorCode)
					.redirectUri(redirectUri)
					.errorDescription(errorDescription)
					.errorUri(errorUri)
					.state(state)
					.build();
			}
		}
	}
}
