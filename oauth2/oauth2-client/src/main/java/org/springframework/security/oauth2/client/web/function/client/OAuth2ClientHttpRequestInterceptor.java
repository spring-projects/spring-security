/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.web.function.client;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Provides an easy mechanism for using an {@link OAuth2AuthorizedClient} to make OAuth
 * 2.0 requests by including the {@link OAuth2AuthorizedClient#getAccessToken() access
 * token} as a bearer token.
 *
 * <p>
 * Example usage:
 *
 * <pre>
 * OAuth2ClientHttpRequestInterceptor requestInterceptor =
 *     new OAuth2ClientHttpRequestInterceptor(authorizedClientManager, clientRegistrationId);
 * RestClient restClient = RestClient.builder()
 *     .requestInterceptor(requestInterceptor)
 *     .build();
 * String response = restClient.get()
 *     .uri(uri)
 *     .retrieve()
 *     .body(String.class);
 * </pre>
 *
 * <h3>Authentication and Authorization Failures</h3>
 *
 * <p>
 * This interceptor has the ability to forward authentication (HTTP 401 Unauthorized) and
 * authorization (HTTP 403 Forbidden) failures from an OAuth 2.0 Resource Server to a
 * {@link OAuth2AuthorizationFailureHandler}. A
 * {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} can be used to remove
 * the cached {@link OAuth2AuthorizedClient}, so that future requests will result in a new
 * token being retrieved from an Authorization Server, and sent to the Resource Server.
 *
 * <p>
 * If either the {@link #setAuthorizedClientRepository(OAuth2AuthorizedClientRepository)}
 * setter or {@link #setAuthorizedClientService(OAuth2AuthorizedClientService)} setter is
 * used, a {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} will be
 * configured automatically.
 *
 * @author Steve Riesenberg
 * @since 6.4
 * @see OAuth2AuthorizedClientManager
 * @see OAuth2AuthorizedClientProvider
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizationFailureHandler
 */
public final class OAuth2ClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

	// @formatter:off
	private static final Map<HttpStatusCode, String> OAUTH2_ERROR_CODES = Map.of(
			HttpStatus.UNAUTHORIZED, OAuth2ErrorCodes.INVALID_TOKEN,
			HttpStatus.FORBIDDEN, OAuth2ErrorCodes.INSUFFICIENT_SCOPE
	);
	// @formatter:on

	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
			"anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private static final String CLIENT_REGISTRATION_ID_ATTR_NAME = OAuth2ClientHttpRequestInterceptor.class.getName()
		.concat(".clientRegistrationId");

	private final OAuth2AuthorizedClientManager authorizedClientManager;

	private String defaultClientRegistrationId;

	// @formatter:off
	private OAuth2AuthorizationFailureHandler authorizationFailureHandler =
			(clientRegistrationId, principal, attributes) -> { };
	// @formatter:on

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	/**
	 * Constructs a {@code OAuth2ClientHttpRequestInterceptor} using the provided
	 * parameters.
	 * @param authorizedClientManager the {@link OAuth2AuthorizedClientManager} which
	 * manages the authorized client(s)
	 */
	public OAuth2ClientHttpRequestInterceptor(OAuth2AuthorizedClientManager authorizedClientManager) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		this.authorizedClientManager = authorizedClientManager;
	}

	/**
	 * Sets the default {@code clientRegistrationId} to be used for resolving an
	 * {@link OAuth2AuthorizedClient}.
	 *
	 * <p>
	 * By default, the {@code clientRegistrationId} is obtained from the current
	 * {@link Authentication principal}. Using this setter overrides the default, but can
	 * be overridden by providing an
	 * {@link RestClient.RequestHeadersSpec#attributes(Consumer) attribute} via
	 * {@link #clientRegistrationId(String)}.
	 * @param clientRegistrationId the default {@code clientRegistrationId}
	 */
	public void setDefaultClientRegistrationId(String clientRegistrationId) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		this.defaultClientRegistrationId = clientRegistrationId;
	}

	/**
	 * Sets the {@link OAuth2AuthorizationFailureHandler} that handles authentication and
	 * authorization failures when communicating to the OAuth 2.0 Resource Server.
	 *
	 * <p>
	 * For example, a {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} is
	 * typically used to remove the cached {@link OAuth2AuthorizedClient}, so that the
	 * same token is no longer used in future requests to the Resource Server.
	 * @param authorizationFailureHandler the {@link OAuth2AuthorizationFailureHandler}
	 * that handles authentication and authorization failures
	 * @see #setAuthorizedClientRepository(OAuth2AuthorizedClientRepository)
	 * @see #setAuthorizedClientService(OAuth2AuthorizedClientService)
	 */
	public void setAuthorizationFailureHandler(OAuth2AuthorizationFailureHandler authorizationFailureHandler) {
		Assert.notNull(authorizationFailureHandler, "authorizationFailureHandler cannot be null");
		this.authorizationFailureHandler = authorizationFailureHandler;
	}

	/**
	 * Sets the {@link OAuth2AuthorizedClientRepository} which is used to set up the
	 * {@link OAuth2AuthorizationFailureHandler} that handles authentication and
	 * authorization failures when communicating to the OAuth 2.0 Resource Server.
	 *
	 * <p>
	 * When this setter is used, authentication (HTTP 401) and authorization (HTTP 403)
	 * failures returned from an OAuth 2.0 Resource Server will be forwarded to a
	 * {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler}, which will
	 * potentially remove the {@link OAuth2AuthorizedClient} from the given
	 * {@link OAuth2AuthorizedClientRepository}, depending on the OAuth 2.0 error code
	 * returned. Authentication failures returned from an OAuth 2.0 Resource Server
	 * typically indicate that the token is invalid, and should not be used in future
	 * requests. Removing the authorized client from the repository will ensure that the
	 * existing token will not be sent for future requests to the Resource Server, and a
	 * new token is retrieved from the Authorization Server and used for future requests
	 * to the Resource Server.
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public void setAuthorizedClientRepository(OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.authorizationFailureHandler = new RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
				(clientRegistrationId, principal, attributes) -> removeAuthorizedClient(authorizedClientRepository,
						clientRegistrationId, principal, attributes));
	}

	private static void removeAuthorizedClient(OAuth2AuthorizedClientRepository authorizedClientRepository,
			String clientRegistrationId, Authentication principal, Map<String, Object> attributes) {
		HttpServletRequest request = (HttpServletRequest) attributes.get(HttpServletRequest.class.getName());
		HttpServletResponse response = (HttpServletResponse) attributes.get(HttpServletResponse.class.getName());
		authorizedClientRepository.removeAuthorizedClient(clientRegistrationId, principal, request, response);
	}

	/**
	 * Sets the {@link OAuth2AuthorizedClientService} which is used to set up the
	 * {@link OAuth2AuthorizationFailureHandler} that handles authentication and
	 * authorization failures when communicating to the OAuth 2.0 Resource Server.
	 *
	 * <p>
	 * When this setter is used, authentication (HTTP 401) and authorization (HTTP 403)
	 * failures returned from an OAuth 2.0 Resource Server will be forwarded to a
	 * {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler}, which will
	 * potentially remove the {@link OAuth2AuthorizedClient} from the given
	 * {@link OAuth2AuthorizedClientService}, depending on the OAuth 2.0 error code
	 * returned. Authentication failures returned from an OAuth 2.0 Resource Server
	 * typically indicate that the token is invalid, and should not be used in future
	 * requests. Removing the authorized client from the repository will ensure that the
	 * existing token will not be sent for future requests to the Resource Server, and a
	 * new token is retrieved from the Authorization Server and used for future requests
	 * to the Resource Server.
	 * @param authorizedClientService the service used to manage authorized clients
	 */
	public void setAuthorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizationFailureHandler = new RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
				(clientRegistrationId, principal, attributes) -> removeAuthorizedClient(authorizedClientService,
						clientRegistrationId, principal));
	}

	private static void removeAuthorizedClient(OAuth2AuthorizedClientService authorizedClientService,
			String clientRegistrationId, Authentication principal) {
		authorizedClientService.removeAuthorizedClient(clientRegistrationId, principal.getName());
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 * @param securityContextHolderStrategy the {@link SecurityContextHolderStrategy} to
	 * use
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	/**
	 * Modifies the {@link ClientHttpRequest#getAttributes() attributes} to include the
	 * {@link ClientRegistration#getRegistrationId() clientRegistrationId} to be used to
	 * look up the {@link OAuth2AuthorizedClient}.
	 * @param clientRegistrationId the {@link ClientRegistration#getRegistrationId()
	 * clientRegistrationId} to be used to look up the {@link OAuth2AuthorizedClient}
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> clientRegistrationId(String clientRegistrationId) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		return (attributes) -> attributes.put(CLIENT_REGISTRATION_ID_ATTR_NAME, clientRegistrationId);
	}

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
			throws IOException {
		Authentication principal = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		authorizeClient(request, principal);
		try {
			ClientHttpResponse response = execution.execute(request, body);
			handleAuthorizationFailure(request, principal, response.getHeaders(), response.getStatusCode());
			return response;
		}
		catch (RestClientResponseException ex) {
			handleAuthorizationFailure(request, principal, ex.getResponseHeaders(), ex.getStatusCode());
			throw ex;
		}
		catch (OAuth2AuthorizationException ex) {
			handleAuthorizationFailure(ex, principal);
			throw ex;
		}
	}

	private void authorizeClient(HttpRequest request, Authentication principal) {
		String clientRegistrationId = clientRegistrationId(request, principal);
		if (clientRegistrationId == null) {
			return;
		}

		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(clientRegistrationId)
				.principal(principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		if (authorizedClient != null) {
			request.getHeaders().setBearerAuth(authorizedClient.getAccessToken().getTokenValue());
		}
	}

	private void handleAuthorizationFailure(HttpRequest request, Authentication principal, HttpHeaders headers,
			HttpStatusCode httpStatus) {
		OAuth2Error error = resolveOAuth2ErrorIfPossible(headers, httpStatus);
		if (error == null) {
			return;
		}

		String clientRegistrationId = clientRegistrationId(request, principal);
		if (clientRegistrationId == null) {
			return;
		}

		ClientAuthorizationException authorizationException = new ClientAuthorizationException(error,
				clientRegistrationId);
		handleAuthorizationFailure(authorizationException, principal);
	}

	private static OAuth2Error resolveOAuth2ErrorIfPossible(HttpHeaders headers, HttpStatusCode httpStatus) {
		String wwwAuthenticateHeader = headers.getFirst(HttpHeaders.WWW_AUTHENTICATE);
		if (wwwAuthenticateHeader != null) {
			Map<String, String> parameters = parseWwwAuthenticateHeader(wwwAuthenticateHeader);
			if (parameters.containsKey(OAuth2ParameterNames.ERROR)) {
				return new OAuth2Error(parameters.get(OAuth2ParameterNames.ERROR),
						parameters.get(OAuth2ParameterNames.ERROR_DESCRIPTION),
						parameters.get(OAuth2ParameterNames.ERROR_URI));
			}
		}

		String errorCode = OAUTH2_ERROR_CODES.get(httpStatus);
		if (errorCode != null) {
			return new OAuth2Error(errorCode, null, "https://tools.ietf.org/html/rfc6750#section-3.1");
		}

		return null;
	}

	private static Map<String, String> parseWwwAuthenticateHeader(String wwwAuthenticateHeader) {
		if (!StringUtils.hasLength(wwwAuthenticateHeader)
				|| !StringUtils.startsWithIgnoreCase(wwwAuthenticateHeader, "bearer")) {
			return Map.of();
		}

		String headerValue = wwwAuthenticateHeader.substring("bearer".length()).stripLeading();
		Map<String, String> parameters = new HashMap<>();
		for (String kvPair : StringUtils.delimitedListToStringArray(headerValue, ",")) {
			String[] kv = StringUtils.split(kvPair, "=");
			if (kv == null || kv.length <= 1) {
				continue;
			}

			parameters.put(kv[0].trim(), kv[1].trim().replace("\"", ""));
		}

		return parameters;
	}

	private String clientRegistrationId(HttpRequest request, Authentication principal) {
		String clientRegistrationId = (String) request.getAttributes().get(CLIENT_REGISTRATION_ID_ATTR_NAME);
		if (clientRegistrationId == null) {
			clientRegistrationId = this.defaultClientRegistrationId;
		}
		if (clientRegistrationId == null && principal instanceof OAuth2AuthenticationToken authentication) {
			clientRegistrationId = authentication.getAuthorizedClientRegistrationId();
		}

		return clientRegistrationId;
	}

	private void handleAuthorizationFailure(OAuth2AuthorizationException authorizationException,
			Authentication principal) {
		ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder
			.getRequestAttributes();
		Map<String, Object> attributes = new HashMap<>();
		if (requestAttributes != null) {
			attributes.put(HttpServletRequest.class.getName(), requestAttributes.getRequest());
			if (requestAttributes.getResponse() != null) {
				attributes.put(HttpServletResponse.class.getName(), requestAttributes.getResponse());
			}
		}

		this.authorizationFailureHandler.onAuthorizationFailure(authorizationException, principal, attributes);
	}

}
