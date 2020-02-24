/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.oauth2.client.web.reactive.function.client;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.context.Context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Provides an easy mechanism for using an {@link OAuth2AuthorizedClient} to make OAuth 2.0 requests
 * by including the {@link OAuth2AuthorizedClient#getAccessToken() access token} as a bearer token.
 *
 * <p>
 * <b>NOTE:</b>This class is intended to be used in a {@code Servlet} environment.
 *
 * <p>
 * Example usage:
 *
 * <pre>
 * ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
 * WebClient webClient = WebClient.builder()
 *    .apply(oauth2.oauth2Configuration())
 *    .build();
 * Mono<String> response = webClient
 *    .get()
 *    .uri(uri)
 *    .attributes(oauth2AuthorizedClient(authorizedClient))
 *    // ...
 *    .retrieve()
 *    .bodyToMono(String.class);
 * </pre>
 *
 * <h3>Authentication and Authorization Failures</h3>
 *
 * <p>
 * Since 5.3, this filter function has the ability to forward authentication (HTTP 401 Unauthorized)
 * and authorization (HTTP 403 Forbidden) failures from an OAuth 2.0 Resource Server
 * to a {@link OAuth2AuthorizationFailureHandler}.
 * A {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} can be used
 * to remove the cached {@link OAuth2AuthorizedClient}, so that future requests will result
 * in a new token being retrieved from an Authorization Server, and sent to the Resource Server.
 *
 * <p>
 * If the {@link #ServletOAuth2AuthorizedClientExchangeFilterFunction(ClientRegistrationRepository, OAuth2AuthorizedClientRepository)}
 * constructor is used, a {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler}
 * will be configured automatically.
 *
 * <p>
 * If the {@link #ServletOAuth2AuthorizedClientExchangeFilterFunction(OAuth2AuthorizedClientManager)}
 * constructor is used, a {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler}
 * will <em>NOT</em> be configured automatically.
 * It is recommended that you configure one via {@link #setAuthorizationFailureHandler(OAuth2AuthorizationFailureHandler)}.
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @author Roman Matiushchenko
 * @since 5.1
 * @see OAuth2AuthorizedClientManager
 * @see DefaultOAuth2AuthorizedClientManager
 * @see OAuth2AuthorizedClientProvider
 * @see OAuth2AuthorizedClientProviderBuilder
 */
public final class ServletOAuth2AuthorizedClientExchangeFilterFunction implements ExchangeFilterFunction {

	// Same key as in SecurityReactorContextConfiguration.SecurityReactorContextSubscriber.SECURITY_CONTEXT_ATTRIBUTES
	static final String SECURITY_REACTOR_CONTEXT_ATTRIBUTES_KEY = "org.springframework.security.SECURITY_CONTEXT_ATTRIBUTES";

	/**
	 * The request attribute name used to locate the {@link OAuth2AuthorizedClient}.
	 */
	private static final String OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME = OAuth2AuthorizedClient.class.getName();

	private static final String CLIENT_REGISTRATION_ID_ATTR_NAME = OAuth2AuthorizedClient.class.getName().concat(".CLIENT_REGISTRATION_ID");
	private static final String AUTHENTICATION_ATTR_NAME = Authentication.class.getName();
	private static final String HTTP_SERVLET_REQUEST_ATTR_NAME = HttpServletRequest.class.getName();
	private static final String HTTP_SERVLET_RESPONSE_ATTR_NAME = HttpServletResponse.class.getName();

	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
			"anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@Deprecated
	private Duration accessTokenExpiresSkew = Duration.ofMinutes(1);

	@Deprecated
	private OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient;

	private OAuth2AuthorizedClientManager authorizedClientManager;

	private boolean defaultAuthorizedClientManager;

	private boolean defaultOAuth2AuthorizedClient;

	private String defaultClientRegistrationId;

	private ClientResponseHandler clientResponseHandler;

	@FunctionalInterface
	private interface ClientResponseHandler {
		Mono<ClientResponse> handleResponse(ClientRequest request, Mono<ClientResponse> response);
	}

	public ServletOAuth2AuthorizedClientExchangeFilterFunction() {
	}

	/**
	 * Constructs a {@code ServletOAuth2AuthorizedClientExchangeFilterFunction} using the provided parameters.
	 *
	 * <p>
	 * When this constructor is used, authentication (HTTP 401) and authorization (HTTP 403)
	 * failures returned from an OAuth 2.0 Resource Server will <em>NOT</em> be forwarded to an
	 * {@link OAuth2AuthorizationFailureHandler}.
	 * Therefore, future requests to the Resource Server will most likely use the same (likely invalid) token,
	 * resulting in the same errors returned from the Resource Server.
	 * It is recommended to configure a {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler}
	 * via {@link #setAuthorizationFailureHandler(OAuth2AuthorizationFailureHandler)}
	 * so that authentication and authorization failures returned from a Resource Server
	 * will result in removing the authorized client, so that a new token is retrieved for future requests.
	 *
	 * @since 5.2
	 * @param authorizedClientManager the {@link OAuth2AuthorizedClientManager} which manages the authorized client(s)
	 */
	public ServletOAuth2AuthorizedClientExchangeFilterFunction(OAuth2AuthorizedClientManager authorizedClientManager) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		this.authorizedClientManager = authorizedClientManager;
		this.clientResponseHandler =  (request, responseMono) -> responseMono;
	}

	/**
	 * Constructs a {@code ServletOAuth2AuthorizedClientExchangeFilterFunction} using the provided parameters.
	 *
	 * <p>
	 * Since 5.3, when this constructor is used, authentication (HTTP 401)
	 * and authorization (HTTP 403) failures returned from an OAuth 2.0 Resource Server
	 * will be forwarded to a {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler},
	 * which will potentially remove the {@link OAuth2AuthorizedClient} from the given
	 * {@link OAuth2AuthorizedClientRepository}, depending on the OAuth 2.0 error code returned.
	 * Authentication failures returned from an OAuth 2.0 Resource Server typically indicate
	 * that the token is invalid, and should not be used in future requests.
	 * Removing the authorized client from the repository will ensure that the existing
	 * token will not be sent for future requests to the Resource Server,
	 * and a new token is retrieved from the Authorization Server and used for
	 * future requests to the Resource Server.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public ServletOAuth2AuthorizedClientExchangeFilterFunction(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		OAuth2AuthorizationFailureHandler authorizationFailureHandler =
				new RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
						(clientRegistrationId, principal, attributes) ->
								authorizedClientRepository.removeAuthorizedClient(clientRegistrationId, principal,
										(HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
										(HttpServletResponse) attributes.get(HttpServletResponse.class.getName())));
		this.authorizedClientManager = createDefaultAuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository, authorizationFailureHandler);
		this.defaultAuthorizedClientManager = true;
		this.clientResponseHandler = new AuthorizationFailureForwarder(authorizationFailureHandler);
	}

	private static OAuth2AuthorizedClientManager createDefaultAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			OAuth2AuthorizationFailureHandler authorizationFailureHandler) {

		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken()
						.clientCredentials()
						.password()
						.build();
		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		authorizedClientManager.setAuthorizationFailureHandler(authorizationFailureHandler);

		return authorizedClientManager;
	}

	/**
	 * Sets the {@link OAuth2AccessTokenResponseClient} used for getting an {@link OAuth2AuthorizedClient} for the client_credentials grant.
	 *
	 * @deprecated Use {@link #ServletOAuth2AuthorizedClientExchangeFilterFunction(OAuth2AuthorizedClientManager)} instead.
	 * 				Create an instance of {@link ClientCredentialsOAuth2AuthorizedClientProvider} configured with a
	 * 				{@link ClientCredentialsOAuth2AuthorizedClientProvider#setAccessTokenResponseClient(OAuth2AccessTokenResponseClient) DefaultClientCredentialsTokenResponseClient}
	 * 				(or a custom one) and than supply it to {@link DefaultOAuth2AuthorizedClientManager#setAuthorizedClientProvider(OAuth2AuthorizedClientProvider) DefaultOAuth2AuthorizedClientManager}.
	 *
	 * @param clientCredentialsTokenResponseClient the client to use
	 */
	@Deprecated
	public void setClientCredentialsTokenResponseClient(
			OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient) {
		Assert.notNull(clientCredentialsTokenResponseClient, "clientCredentialsTokenResponseClient cannot be null");
		Assert.state(this.defaultAuthorizedClientManager, "The client cannot be set when the constructor used is \"ServletOAuth2AuthorizedClientExchangeFilterFunction(OAuth2AuthorizedClientManager)\". " +
				"Instead, use the constructor \"ServletOAuth2AuthorizedClientExchangeFilterFunction(ClientRegistrationRepository, OAuth2AuthorizedClientRepository)\".");
		this.clientCredentialsTokenResponseClient = clientCredentialsTokenResponseClient;
		updateDefaultAuthorizedClientManager();
	}

	private void updateDefaultAuthorizedClientManager() {
		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken(configurer -> configurer.clockSkew(this.accessTokenExpiresSkew))
						.clientCredentials(this::updateClientCredentialsProvider)
						.password(configurer -> configurer.clockSkew(this.accessTokenExpiresSkew))
						.build();
		((DefaultOAuth2AuthorizedClientManager) this.authorizedClientManager).setAuthorizedClientProvider(authorizedClientProvider);
	}

	private void updateClientCredentialsProvider(OAuth2AuthorizedClientProviderBuilder.ClientCredentialsGrantBuilder builder) {
		if (this.clientCredentialsTokenResponseClient != null) {
			builder.accessTokenResponseClient(this.clientCredentialsTokenResponseClient);
		}
		builder.clockSkew(this.accessTokenExpiresSkew);
	}

	/**
	 * If true, a default {@link OAuth2AuthorizedClient} can be discovered from the current Authentication. It is
	 * recommended to be cautious with this feature since all HTTP requests will receive the access token if it can be
	 * resolved from the current Authentication.
	 * @param defaultOAuth2AuthorizedClient true if a default {@link OAuth2AuthorizedClient} should be used, else false.
	 *                                      Default is false.
	 */
	public void setDefaultOAuth2AuthorizedClient(boolean defaultOAuth2AuthorizedClient) {
		this.defaultOAuth2AuthorizedClient = defaultOAuth2AuthorizedClient;
	}

	/**
	 * If set, will be used as the default {@link ClientRegistration#getRegistrationId()}. It is
	 * recommended to be cautious with this feature since all HTTP requests will receive the access token.
	 * @param clientRegistrationId the id to use
	 */
	public void setDefaultClientRegistrationId(String clientRegistrationId) {
		this.defaultClientRegistrationId = clientRegistrationId;
	}

	/**
	 * Configures the builder with {@link #defaultRequest()} and adds this as a {@link ExchangeFilterFunction}
	 * @return the {@link Consumer} to configure the builder
	 */
	public Consumer<WebClient.Builder> oauth2Configuration() {
		return builder -> builder.defaultRequest(defaultRequest()).filter(this);
	}

	/**
	 * Provides defaults for the {@link HttpServletRequest} and the {@link HttpServletResponse} using
	 * {@link RequestContextHolder}. It also provides defaults for the {@link Authentication} using
	 * {@link SecurityContextHolder}. It also can default the {@link OAuth2AuthorizedClient} using the
	 * {@link #clientRegistrationId(String)} or the {@link #authentication(Authentication)}.
	 * @return the {@link Consumer} to populate the attributes
	 */
	public Consumer<WebClient.RequestHeadersSpec<?>> defaultRequest() {
		return spec -> spec.attributes(attrs -> {
			populateDefaultRequestResponse(attrs);
			populateDefaultAuthentication(attrs);
		});
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link OAuth2AuthorizedClient} to be used for
	 * providing the Bearer Token.
	 *
	 * @param authorizedClient the {@link OAuth2AuthorizedClient} to use.
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> oauth2AuthorizedClient(OAuth2AuthorizedClient authorizedClient) {
		return attributes -> {
			if (authorizedClient == null) {
				attributes.remove(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME);
			} else {
				attributes.put(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME, authorizedClient);
			}
		};
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link ClientRegistration#getRegistrationId()} to
	 * be used to look up the {@link OAuth2AuthorizedClient}.
	 *
	 * @param clientRegistrationId the {@link ClientRegistration#getRegistrationId()} to
	 * be used to look up the {@link OAuth2AuthorizedClient}.
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> clientRegistrationId(String clientRegistrationId) {
		return attributes -> attributes.put(CLIENT_REGISTRATION_ID_ATTR_NAME, clientRegistrationId);
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link Authentication} used to
	 * look up and save the {@link OAuth2AuthorizedClient}. The value is defaulted in
	 * {@link ServletOAuth2AuthorizedClientExchangeFilterFunction#defaultRequest()}
	 *
	 * @param authentication the {@link Authentication} to use.
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> authentication(Authentication authentication) {
		return attributes -> attributes.put(AUTHENTICATION_ATTR_NAME, authentication);
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link HttpServletRequest} used to
	 * look up and save the {@link OAuth2AuthorizedClient}. The value is defaulted in
	 * {@link ServletOAuth2AuthorizedClientExchangeFilterFunction#defaultRequest()}
	 *
	 * @param request the {@link HttpServletRequest} to use.
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> httpServletRequest(HttpServletRequest request) {
		return attributes -> attributes.put(HTTP_SERVLET_REQUEST_ATTR_NAME, request);
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link HttpServletResponse} used to
	 * save the {@link OAuth2AuthorizedClient}. The value is defaulted in
	 * {@link ServletOAuth2AuthorizedClientExchangeFilterFunction#defaultRequest()}
	 *
	 * @param response the {@link HttpServletResponse} to use.
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> httpServletResponse(HttpServletResponse response) {
		return attributes -> attributes.put(HTTP_SERVLET_RESPONSE_ATTR_NAME, response);
	}

	/**
	 * An access token will be considered expired by comparing its expiration to now +
	 * this skewed Duration. The default is 1 minute.
	 *
	 * @deprecated The {@code accessTokenExpiresSkew} should be configured with the specific {@link OAuth2AuthorizedClientProvider} implementation,
	 * 				e.g. {@link ClientCredentialsOAuth2AuthorizedClientProvider#setClockSkew(Duration) ClientCredentialsOAuth2AuthorizedClientProvider} or
	 * 				{@link RefreshTokenOAuth2AuthorizedClientProvider#setClockSkew(Duration) RefreshTokenOAuth2AuthorizedClientProvider}.
	 *
	 * @param accessTokenExpiresSkew the Duration to use.
	 */
	@Deprecated
	public void setAccessTokenExpiresSkew(Duration accessTokenExpiresSkew) {
		Assert.notNull(accessTokenExpiresSkew, "accessTokenExpiresSkew cannot be null");
		Assert.state(this.defaultAuthorizedClientManager, "The accessTokenExpiresSkew cannot be set when the constructor used is \"ServletOAuth2AuthorizedClientExchangeFilterFunction(OAuth2AuthorizedClientManager)\". " +
				"Instead, use the constructor \"ServletOAuth2AuthorizedClientExchangeFilterFunction(ClientRegistrationRepository, OAuth2AuthorizedClientRepository)\".");
		this.accessTokenExpiresSkew = accessTokenExpiresSkew;
		updateDefaultAuthorizedClientManager();
	}

	/**
	 * Sets the {@link OAuth2AuthorizationFailureHandler} that handles
	 * authentication and authorization failures when communicating
	 * to the OAuth 2.0 Resource Server.
	 *
	 * <p>
	 * For example, a {@link RemoveAuthorizedClientOAuth2AuthorizationFailureHandler}
	 * is typically used to remove the cached {@link OAuth2AuthorizedClient},
	 * so that the same token is no longer used in future requests to the Resource Server.
	 *
	 * <p>
	 * The failure handler used by default depends on which constructor was used
	 * to construct this {@link ServletOAuth2AuthorizedClientExchangeFilterFunction}.
	 * See the constructors for more details.
	 *
	 * @param authorizationFailureHandler the {@link OAuth2AuthorizationFailureHandler} that handles authentication and authorization failures
	 * @since 5.3
	 */
	public void setAuthorizationFailureHandler(OAuth2AuthorizationFailureHandler authorizationFailureHandler) {
		Assert.notNull(authorizationFailureHandler, "authorizationFailureHandler cannot be null");
		this.clientResponseHandler = new AuthorizationFailureForwarder(authorizationFailureHandler);
	}

	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		return mergeRequestAttributesIfNecessary(request)
				.filter(req -> req.attribute(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME).isPresent())
				.flatMap(req -> reauthorizeClient(getOAuth2AuthorizedClient(req.attributes()), req))
				.switchIfEmpty(Mono.defer(() ->
						mergeRequestAttributesIfNecessary(request)
								.filter(req -> resolveClientRegistrationId(req) != null)
								.flatMap(req -> authorizeClient(resolveClientRegistrationId(req), req))
				))
				.map(authorizedClient -> bearer(request, authorizedClient))
				.flatMap(requestWithBearer -> exchangeAndHandleResponse(requestWithBearer, next))
				.switchIfEmpty(Mono.defer(() -> exchangeAndHandleResponse(request, next)));
	}

	private Mono<ClientResponse> exchangeAndHandleResponse(ClientRequest request, ExchangeFunction next) {
		return next.exchange(request)
				.transform(responseMono -> this.clientResponseHandler.handleResponse(request, responseMono));
	}

	private Mono<ClientRequest> mergeRequestAttributesIfNecessary(ClientRequest request) {
		if (!request.attribute(HTTP_SERVLET_REQUEST_ATTR_NAME).isPresent() ||
				!request.attribute(HTTP_SERVLET_RESPONSE_ATTR_NAME).isPresent() ||
				!request.attribute(AUTHENTICATION_ATTR_NAME).isPresent()) {
			return mergeRequestAttributesFromContext(request);
		} else {
			return Mono.just(request);
		}
	}

	private Mono<ClientRequest> mergeRequestAttributesFromContext(ClientRequest request) {
		ClientRequest.Builder builder = ClientRequest.from(request);
		return Mono.subscriberContext()
				.map(ctx -> builder.attributes(attrs -> populateRequestAttributes(attrs, ctx)))
				.map(ClientRequest.Builder::build);
	}

	private void populateRequestAttributes(Map<String, Object> attrs, Context ctx) {
		// NOTE: SecurityReactorContextConfiguration.SecurityReactorContextSubscriber adds this key
		if (!ctx.hasKey(SECURITY_REACTOR_CONTEXT_ATTRIBUTES_KEY)) {
			return;
		}
		Map<Object, Object> contextAttributes = ctx.get(SECURITY_REACTOR_CONTEXT_ATTRIBUTES_KEY);
		HttpServletRequest servletRequest = (HttpServletRequest) contextAttributes.get(HttpServletRequest.class);
		if (servletRequest != null) {
			attrs.putIfAbsent(HTTP_SERVLET_REQUEST_ATTR_NAME, servletRequest);
		}
		HttpServletResponse servletResponse = (HttpServletResponse) contextAttributes.get(HttpServletResponse.class);
		if (servletResponse != null) {
			attrs.putIfAbsent(HTTP_SERVLET_RESPONSE_ATTR_NAME, servletResponse);
		}
		Authentication authentication = (Authentication) contextAttributes.get(Authentication.class);
		if (authentication != null) {
			attrs.putIfAbsent(AUTHENTICATION_ATTR_NAME, authentication);
		}
	}

	private void populateDefaultRequestResponse(Map<String, Object> attrs) {
		if (attrs.containsKey(HTTP_SERVLET_REQUEST_ATTR_NAME) &&
				attrs.containsKey(HTTP_SERVLET_RESPONSE_ATTR_NAME)) {
			return;
		}
		RequestAttributes context = RequestContextHolder.getRequestAttributes();
		if (context instanceof ServletRequestAttributes) {
			attrs.putIfAbsent(HTTP_SERVLET_REQUEST_ATTR_NAME,  ((ServletRequestAttributes) context).getRequest());
			attrs.putIfAbsent(HTTP_SERVLET_RESPONSE_ATTR_NAME, ((ServletRequestAttributes) context).getResponse());
		}
	}

	private void populateDefaultAuthentication(Map<String, Object> attrs) {
		if (attrs.containsKey(AUTHENTICATION_ATTR_NAME)) {
			return;
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		attrs.putIfAbsent(AUTHENTICATION_ATTR_NAME, authentication);
	}

	private String resolveClientRegistrationId(ClientRequest request) {
		Map<String, Object> attrs = request.attributes();
		String clientRegistrationId = getClientRegistrationId(attrs);
		if (clientRegistrationId == null) {
			clientRegistrationId = this.defaultClientRegistrationId;
		}
		Authentication authentication = getAuthentication(attrs);
		if (clientRegistrationId == null
				&& this.defaultOAuth2AuthorizedClient
				&& authentication instanceof OAuth2AuthenticationToken) {
			clientRegistrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
		}
		return clientRegistrationId;
	}

	private Mono<OAuth2AuthorizedClient> authorizeClient(String clientRegistrationId, ClientRequest request) {
		if (this.authorizedClientManager == null) {
			return Mono.empty();
		}
		Map<String, Object> attrs = request.attributes();
		Authentication authentication = getAuthentication(attrs);
		if (authentication == null) {
			authentication = ANONYMOUS_AUTHENTICATION;
		}
		HttpServletRequest servletRequest = getRequest(attrs);
		HttpServletResponse servletResponse = getResponse(attrs);

		OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId).principal(authentication);
		builder.attributes(attributes -> {
			if (servletRequest != null) {
				attributes.put(HttpServletRequest.class.getName(), servletRequest);
			}
			if (servletResponse != null) {
				attributes.put(HttpServletResponse.class.getName(), servletResponse);
			}
		});
		OAuth2AuthorizeRequest authorizeRequest = builder.build();

		// NOTE:
		// 'authorizedClientManager.authorize()' needs to be executed
		// on a dedicated thread via subscribeOn(Schedulers.boundedElastic())
		// since it performs a blocking I/O operation using RestTemplate internally
		return Mono.fromSupplier(() -> this.authorizedClientManager.authorize(authorizeRequest)).subscribeOn(Schedulers.boundedElastic());
	}

	private Mono<OAuth2AuthorizedClient> reauthorizeClient(OAuth2AuthorizedClient authorizedClient, ClientRequest request) {
		if (this.authorizedClientManager == null) {
			return Mono.just(authorizedClient);
		}
		Map<String, Object> attrs = request.attributes();
		Authentication authentication = getAuthentication(attrs);
		if (authentication == null) {
			authentication = createAuthentication(authorizedClient.getPrincipalName());
		}
		HttpServletRequest servletRequest = getRequest(attrs);
		HttpServletResponse servletResponse = getResponse(attrs);

		OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest.withAuthorizedClient(authorizedClient).principal(authentication);
		builder.attributes(attributes -> {
			if (servletRequest != null) {
				attributes.put(HttpServletRequest.class.getName(), servletRequest);
			}
			if (servletResponse != null) {
				attributes.put(HttpServletResponse.class.getName(), servletResponse);
			}
		});
		OAuth2AuthorizeRequest reauthorizeRequest = builder.build();

		// NOTE:
		// 'authorizedClientManager.authorize()' needs to be executed
		// on a dedicated thread via subscribeOn(Schedulers.boundedElastic())
		// since it performs a blocking I/O operation using RestTemplate internally
		return Mono.fromSupplier(() -> this.authorizedClientManager.authorize(reauthorizeRequest)).subscribeOn(Schedulers.boundedElastic());
	}

	private ClientRequest bearer(ClientRequest request, OAuth2AuthorizedClient authorizedClient) {
		return ClientRequest.from(request)
					.headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
					.attributes(oauth2AuthorizedClient(authorizedClient))
					.build();
	}

	static OAuth2AuthorizedClient getOAuth2AuthorizedClient(Map<String, Object> attrs) {
		return (OAuth2AuthorizedClient) attrs.get(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME);
	}

	static String getClientRegistrationId(Map<String, Object> attrs) {
		return (String) attrs.get(CLIENT_REGISTRATION_ID_ATTR_NAME);
	}

	static Authentication getAuthentication(Map<String, Object> attrs) {
		return (Authentication) attrs.get(AUTHENTICATION_ATTR_NAME);
	}

	static HttpServletRequest getRequest(Map<String, Object> attrs) {
		return (HttpServletRequest) attrs.get(HTTP_SERVLET_REQUEST_ATTR_NAME);
	}

	static HttpServletResponse getResponse(Map<String, Object> attrs) {
		return (HttpServletResponse) attrs.get(HTTP_SERVLET_RESPONSE_ATTR_NAME);
	}

	private static Authentication createAuthentication(final String principalName) {
		Assert.hasText(principalName, "principalName cannot be empty");

		return new AbstractAuthenticationToken(null) {
			@Override
			public Object getCredentials() {
				return "";
			}

			@Override
			public Object getPrincipal() {
				return principalName;
			}
		};
	}

	/**
	 * Forwards authentication and authorization failures to an
	 * {@link OAuth2AuthorizationFailureHandler}.
	 *
	 * @since 5.3
	 */
	private static class AuthorizationFailureForwarder implements ClientResponseHandler {

		/**
		 * A map of HTTP status code to OAuth 2.0 error code for
		 * HTTP status codes that should be interpreted as
		 * authentication or authorization failures.
		 */
		private final Map<Integer, String> httpStatusToOAuth2ErrorCodeMap;

		/**
		 * The {@link OAuth2AuthorizationFailureHandler} to notify
		 * when an authentication/authorization failure occurs.
		 */
		private final OAuth2AuthorizationFailureHandler authorizationFailureHandler;

		private AuthorizationFailureForwarder(OAuth2AuthorizationFailureHandler authorizationFailureHandler) {
			Assert.notNull(authorizationFailureHandler, "authorizationFailureHandler cannot be null");
			this.authorizationFailureHandler = authorizationFailureHandler;

			Map<Integer, String> httpStatusToOAuth2Error = new HashMap<>();
			httpStatusToOAuth2Error.put(HttpStatus.UNAUTHORIZED.value(), OAuth2ErrorCodes.INVALID_TOKEN);
			httpStatusToOAuth2Error.put(HttpStatus.FORBIDDEN.value(), OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
			this.httpStatusToOAuth2ErrorCodeMap = Collections.unmodifiableMap(httpStatusToOAuth2Error);
		}

		@Override
		public Mono<ClientResponse> handleResponse(ClientRequest request, Mono<ClientResponse> responseMono) {
			return responseMono
					.flatMap(response -> handleResponse(request, response)
							.thenReturn(response))
					.onErrorResume(WebClientResponseException.class, e -> handleWebClientResponseException(request, e)
							.then(Mono.error(e)))
					.onErrorResume(OAuth2AuthorizationException.class, e -> handleAuthorizationException(request, e)
							.then(Mono.error(e)));
		}

		private Mono<Void> handleResponse(ClientRequest request, ClientResponse response) {
			return Mono.justOrEmpty(resolveErrorIfPossible(response))
					.flatMap(oauth2Error -> {
						Map<String, Object> attrs = request.attributes();
						OAuth2AuthorizedClient authorizedClient = getOAuth2AuthorizedClient(attrs);
						if (authorizedClient == null) {
							return Mono.empty();
						}

						ClientAuthorizationException authorizationException = new ClientAuthorizationException(
								oauth2Error, authorizedClient.getClientRegistration().getRegistrationId());

						Authentication principal = createAuthentication(authorizedClient.getPrincipalName());
						HttpServletRequest servletRequest = getRequest(attrs);
						HttpServletResponse servletResponse = getResponse(attrs);

						return handleAuthorizationFailure(authorizationException, principal, servletRequest, servletResponse);
					});
		}

		private OAuth2Error resolveErrorIfPossible(ClientResponse response) {
			// Try to resolve from 'WWW-Authenticate' header
			if (!response.headers().header(HttpHeaders.WWW_AUTHENTICATE).isEmpty()) {
				String wwwAuthenticateHeader = response.headers().header(HttpHeaders.WWW_AUTHENTICATE).get(0);
				Map<String, String> authParameters = parseAuthParameters(wwwAuthenticateHeader);
				if (authParameters.containsKey(OAuth2ParameterNames.ERROR)) {
					return new OAuth2Error(
							authParameters.get(OAuth2ParameterNames.ERROR),
							authParameters.get(OAuth2ParameterNames.ERROR_DESCRIPTION),
							authParameters.get(OAuth2ParameterNames.ERROR_URI));
				}
			}
			return resolveErrorIfPossible(response.rawStatusCode());
		}

		private OAuth2Error resolveErrorIfPossible(int statusCode) {
			if (this.httpStatusToOAuth2ErrorCodeMap.containsKey(statusCode)) {
				return new OAuth2Error(
						this.httpStatusToOAuth2ErrorCodeMap.get(statusCode),
						null,
						"https://tools.ietf.org/html/rfc6750#section-3.1");
			}
			return null;
		}

		private Map<String, String> parseAuthParameters(String wwwAuthenticateHeader) {
			return Stream.of(wwwAuthenticateHeader)
					.filter(header -> !StringUtils.isEmpty(header))
					.filter(header -> header.toLowerCase().startsWith("bearer"))
					.map(header -> header.substring("bearer".length()))
					.map(header -> header.split(","))
					.flatMap(Stream::of)
					.map(parameter -> parameter.split("="))
					.filter(parameter -> parameter.length > 1)
					.collect(Collectors.toMap(
							parameters -> parameters[0].trim(),
							parameters -> parameters[1].trim().replace("\"", "")));
		}

		/**
		 * Handles the given http status code returned from a resource server
		 * by notifying the authorization failure handler if the http status
		 * code is in the {@link #httpStatusToOAuth2ErrorCodeMap}.
		 *
		 * @param request the request being processed
		 * @param exception The root cause exception for the failure
		 * @return a {@link Mono} that completes empty after the authorization failure handler completes
		 */
		private Mono<Void> handleWebClientResponseException(ClientRequest request, WebClientResponseException exception) {
			return Mono.justOrEmpty(resolveErrorIfPossible(exception.getRawStatusCode()))
					.flatMap(oauth2Error -> {
						Map<String, Object> attrs = request.attributes();
						OAuth2AuthorizedClient authorizedClient = getOAuth2AuthorizedClient(attrs);
						if (authorizedClient == null) {
							return Mono.empty();
						}

						ClientAuthorizationException authorizationException = new ClientAuthorizationException(
								oauth2Error, authorizedClient.getClientRegistration().getRegistrationId(), exception);

						Authentication principal = createAuthentication(authorizedClient.getPrincipalName());
						HttpServletRequest servletRequest = getRequest(attrs);
						HttpServletResponse servletResponse = getResponse(attrs);

						return handleAuthorizationFailure(authorizationException, principal, servletRequest, servletResponse);
					});
		}

		/**
		 * Handles the given {@link OAuth2AuthorizationException} that occurred downstream
		 * by notifying the authorization failure handler.
		 *
		 * @param request the request being processed
		 * @param authorizationException the authorization exception to include in the failure event
		 * @return a {@link Mono} that completes empty after the authorization failure handler completes
		 */
		private Mono<Void> handleAuthorizationException(ClientRequest request, OAuth2AuthorizationException authorizationException) {
			return Mono.justOrEmpty(request)
					.flatMap(req -> {
						Map<String, Object> attrs = req.attributes();
						OAuth2AuthorizedClient authorizedClient = getOAuth2AuthorizedClient(attrs);
						if (authorizedClient == null) {
							return Mono.empty();
						}

						Authentication principal = createAuthentication(authorizedClient.getPrincipalName());
						HttpServletRequest servletRequest = getRequest(attrs);
						HttpServletResponse servletResponse = getResponse(attrs);

						return handleAuthorizationFailure(authorizationException, principal, servletRequest, servletResponse);
					});
		}

		/**
		 * Delegates the failed authorization to the {@link OAuth2AuthorizationFailureHandler}.
		 *
		 * @param exception the {@link OAuth2AuthorizationException} to include in the failure event
		 * @param principal the principal associated with the failed authorization attempt
		 * @param servletRequest the currently active {@code HttpServletRequest}
		 * @param servletResponse the currently active {@code HttpServletResponse}
		 * @return a {@link Mono} that completes empty after the {@link OAuth2AuthorizationFailureHandler} completes
		 */
		private Mono<Void> handleAuthorizationFailure(OAuth2AuthorizationException exception,
				Authentication principal, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
			Runnable runnable = () -> this.authorizationFailureHandler.onAuthorizationFailure(
					exception, principal, createAttributes(servletRequest, servletResponse));
			return Mono.fromRunnable(runnable).subscribeOn(Schedulers.boundedElastic()).then();
		}

		private static Map<String, Object> createAttributes(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
			Map<String, Object> attributes = new HashMap<>();
			attributes.put(HttpServletRequest.class.getName(), servletRequest);
			attributes.put(HttpServletResponse.class.getName(), servletResponse);
			return attributes;
		}
	}
}
