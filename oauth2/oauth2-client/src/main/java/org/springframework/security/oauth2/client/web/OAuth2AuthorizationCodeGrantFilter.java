/*
 * Copyright 2002-2019 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A {@code Filter} for the OAuth 2.0 Authorization Code Grant,
 * which handles the processing of the OAuth 2.0 Authorization Response.
 *
 * <p>
 * The OAuth 2.0 Authorization Response is processed as follows:
 *
 * <ul>
 * <li>
 *	Assuming the End-User (Resource Owner) has granted access to the Client, the Authorization Server will append the
 *	{@link OAuth2ParameterNames#CODE code} and {@link OAuth2ParameterNames#STATE state} parameters
 *	to the {@link OAuth2ParameterNames#REDIRECT_URI redirect_uri} (provided in the Authorization Request)
 *	and redirect the End-User's user-agent back to this {@code Filter} (the Client).
 * </li>
 * <li>
 *  This {@code Filter} will then create an {@link OAuth2AuthorizationCodeAuthenticationToken} with
 *  the {@link OAuth2ParameterNames#CODE code} received and
 *  delegate it to the {@link AuthenticationManager} to authenticate.
 * </li>
 * <li>
 *  Upon a successful authentication, an {@link OAuth2AuthorizedClient Authorized Client} is created by associating the
 *  {@link OAuth2AuthorizationCodeAuthenticationToken#getClientRegistration() client} to the
 *  {@link OAuth2AuthorizationCodeAuthenticationToken#getAccessToken() access token} and current {@code Principal}
 *  and saving it via the {@link OAuth2AuthorizedClientRepository}.
 * </li>
 * </ul>
 *
 * @author Joe Grandja
 * @author Tadaya Tsuyukubo
 * @since 5.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationResponse
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see ClientRegistrationRepository
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public class OAuth2AuthorizationCodeGrantFilter extends OncePerRequestFilter {
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientRepository authorizedClientRepository;
	private final AuthenticationManager authenticationManager;
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
		new HttpSessionOAuth2AuthorizationRequestRepository();
	private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private final RequestCache requestCache = new HttpSessionRequestCache();

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeGrantFilter} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the authorized client repository
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2AuthorizationCodeGrantFilter(ClientRegistrationRepository clientRegistrationRepository,
												OAuth2AuthorizedClientRepository authorizedClientRepository,
												AuthenticationManager authenticationManager) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
		this.authenticationManager = authenticationManager;
	}

	/**
	 * Sets the repository for stored {@link OAuth2AuthorizationRequest}'s.
	 *
	 * @param authorizationRequestRepository the repository for stored {@link OAuth2AuthorizationRequest}'s
	 */
	public final void setAuthorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {

		if (this.shouldProcessAuthorizationResponse(request)) {
			this.processAuthorizationResponse(request, response);
			return;
		}

		filterChain.doFilter(request, response);
	}

	private boolean shouldProcessAuthorizationResponse(HttpServletRequest request) {
		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.loadAuthorizationRequest(request);
		if (authorizationRequest == null) {
			return false;
		}
		MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());

		if (OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params) &&
				isValidRedirectUrl(request, authorizationRequest.getRedirectUri())) {
			return true;
		}
		return false;
	}

	private boolean isValidRedirectUrl(HttpServletRequest httpServletRequest, String redirectUrl) {
		UriComponents request = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(httpServletRequest))
				.replaceQueryParam(OAuth2ParameterNames.CODE)
				.replaceQueryParam(OAuth2ParameterNames.STATE)
				.build();

		UriComponents redirect = UriComponentsBuilder.fromUriString(redirectUrl).build();

		// Simple check first
		if (request.toUriString().equals(redirectUrl)) {
			return true;
		}

		// Compare each part of url one by one

		if (!Objects.equals(request.getScheme(), redirect.getScheme())) {
			return false;
		}

		if (!Objects.equals(request.getUserInfo(), redirect.getUserInfo())) {
			return false;
		}

		if (!Objects.equals(request.getHost(), redirect.getHost())) {
			return false;
		}

		if (!Objects.equals(request.getPort(), redirect.getPort())) {
			return false;
		}

		if (!Objects.equals(request.getPath(), redirect.getPath())) {
			return false;
		}

		if (redirect.getQuery() == null) {
			return true;  // no need to check request query params
		}

		// Compare request param/values are in exact order specified in redirect url.
		// Request(Authorization Response) can have additional parameters appended which is allowed by spec.
		// Since urls are hierarchical, UriComponents uses HierarchicalUriComponents which keeps the exact
		// order of parameters.
		MultiValueMap<String, String> requestParamMap = request.getQueryParams();
		MultiValueMap<String, String> redirectParamMap = redirect.getQueryParams();

		return containsRedirectUriParamsInOrder(requestParamMap, redirectParamMap);

	}

	private boolean containsRedirectUriParamsInOrder(MultiValueMap<String, String> requestMap, MultiValueMap<String, String> redirectMap) {
		Iterator<Map.Entry<String, List<String>>> requestIterator = requestMap.entrySet().iterator();
		Iterator<Map.Entry<String, List<String>>> redirectIterator = redirectMap.entrySet().iterator();

		while (requestIterator.hasNext() && redirectIterator.hasNext()) {
			Map.Entry<String, List<String>> requestEntry = requestIterator.next();
			Map.Entry<String, List<String>> redirectEntry = redirectIterator.next();

			String requestParam = requestEntry.getKey();
			String redirectParam = redirectEntry.getKey();

			if (!requestParam.equals(redirectParam)) {
				return false;  // param doesn't match
			}

			List<String> requestValues = requestEntry.getValue();
			List<String> redirectValues = redirectEntry.getValue();

			if (requestValues.size() < redirectValues.size()) {
				return false;  // request param values don't have ones specified in redirect param
			}
			// request may have additional param values; thus, iterate over redirect values
			for (int i = 0; i < redirectValues.size(); i++) {
				String requestValue = requestValues.get(i);
				String redirectValue = redirectValues.get(i);

				if (!requestValue.equals(redirectValue)) {
					return false;  // request param value doesn't match
				}
			}
		}

		// request may have additional params which is ok by spec

		if (redirectIterator.hasNext()) {
			return false;  // request has less params than redirect params
		}

		return true;
	}

	private void processAuthorizationResponse(HttpServletRequest request, HttpServletResponse response)
		throws IOException {

		OAuth2AuthorizationRequest authorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, response);

		String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

		MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
		String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replaceQueryParam(OAuth2ParameterNames.CODE)
				.replaceQueryParam(OAuth2ParameterNames.STATE)
				.build()
				.toUriString();
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params, redirectUri);

		OAuth2AuthorizationCodeAuthenticationToken authenticationRequest = new OAuth2AuthorizationCodeAuthenticationToken(
			clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
		authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		OAuth2AuthorizationCodeAuthenticationToken authenticationResult;

		try {
			authenticationResult = (OAuth2AuthorizationCodeAuthenticationToken)
				this.authenticationManager.authenticate(authenticationRequest);
		} catch (OAuth2AuthorizationException ex) {
			OAuth2Error error = ex.getError();
			UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authorizationResponse.getRedirectUri())
				.queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
			if (!StringUtils.isEmpty(error.getDescription())) {
				uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
			}
			if (!StringUtils.isEmpty(error.getUri())) {
				uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
			}
			this.redirectStrategy.sendRedirect(request, response, uriBuilder.build().encode().toString());
			return;
		}

		Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
		String principalName = currentAuthentication != null ? currentAuthentication.getName() : "anonymousUser";

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
			authenticationResult.getClientRegistration(),
			principalName,
			authenticationResult.getAccessToken(),
			authenticationResult.getRefreshToken());

		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, currentAuthentication, request, response);

		String redirectUrl = authorizationResponse.getRedirectUri();
		SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		if (savedRequest != null) {
			redirectUrl = savedRequest.getRedirectUrl();
			this.requestCache.removeRequest(request, response);
		}

		this.redirectStrategy.sendRedirect(request, response, redirectUrl);
	}
}
