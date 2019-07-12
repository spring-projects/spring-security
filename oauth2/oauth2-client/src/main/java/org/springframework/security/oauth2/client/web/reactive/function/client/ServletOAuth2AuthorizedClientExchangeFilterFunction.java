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

package org.springframework.security.oauth2.client.web.reactive.function.client;

import org.reactivestreams.Subscription;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2ReauthorizeRequest;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Operators;
import reactor.util.context.Context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Collection;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Provides an easy mechanism for using an {@link OAuth2AuthorizedClient} to make OAuth2 requests by including the
 * token as a Bearer Token. It also provides mechanisms for looking up the {@link OAuth2AuthorizedClient}. This class is
 * intended to be used in a servlet environment.
 *
 * Example usage:
 *
 * <pre>
 * ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(clientRegistrationRepository, authorizedClientRepository);
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
 * An attempt to automatically refresh the token will be made if all of the following
 * are true:
 *
 * <ul>
 * <li>The {@link OAuth2AuthorizedClientManager} is not null</li>
 * <li>A refresh token is present on the {@link OAuth2AuthorizedClient}</li>
 * <li>The access token is expired</li>
 * <li>The {@link SecurityContextHolder} will be used to attempt to save
 * the token. If it is empty, then the principal name on the {@link OAuth2AuthorizedClient}
 * will be used to create an Authentication for saving.</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizedClientManager
 */
public final class ServletOAuth2AuthorizedClientExchangeFilterFunction
		implements ExchangeFilterFunction, InitializingBean, DisposableBean {

	/**
	 * The request attribute name used to locate the {@link OAuth2AuthorizedClient}.
	 */
	private static final String OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME = OAuth2AuthorizedClient.class.getName();
	private static final String CLIENT_REGISTRATION_ID_ATTR_NAME = OAuth2AuthorizedClient.class.getName().concat(".CLIENT_REGISTRATION_ID");
	private static final String AUTHENTICATION_ATTR_NAME = Authentication.class.getName();
	private static final String HTTP_SERVLET_REQUEST_ATTR_NAME = HttpServletRequest.class.getName();
	private static final String HTTP_SERVLET_RESPONSE_ATTR_NAME = HttpServletResponse.class.getName();

	private static final String REQUEST_CONTEXT_OPERATOR_KEY = RequestContextSubscriber.class.getName();

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

	public ServletOAuth2AuthorizedClientExchangeFilterFunction() {
	}

	/**
	 * Constructs a {@code ServletOAuth2AuthorizedClientExchangeFilterFunction} using the provided parameters.
	 *
	 * @since 5.2
	 * @param authorizedClientManager the {@link OAuth2AuthorizedClientManager} which manages the authorized client(s)
	 */
	public ServletOAuth2AuthorizedClientExchangeFilterFunction(OAuth2AuthorizedClientManager authorizedClientManager) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		this.authorizedClientManager = authorizedClientManager;
	}

	/**
	 * Constructs a {@code ServletOAuth2AuthorizedClientExchangeFilterFunction} using the provided parameters.
	 *
	 * @deprecated Use {@link #ServletOAuth2AuthorizedClientExchangeFilterFunction(OAuth2AuthorizedClientManager)} instead.
	 * 				See {@link DefaultOAuth2AuthorizedClientManager} and {@link OAuth2AuthorizedClientProviderBuilder}.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	@Deprecated
	public ServletOAuth2AuthorizedClientExchangeFilterFunction(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {
		this.authorizedClientManager = createDefaultAuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
		this.defaultAuthorizedClientManager = true;
	}

	private static OAuth2AuthorizedClientManager createDefaultAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientRepository authorizedClientRepository) {

		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.withProvider()
						.authorizationCode()
						.refreshToken()
						.clientCredentials()
						.build();
		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		return authorizedClientManager;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Hooks.onLastOperator(REQUEST_CONTEXT_OPERATOR_KEY, Operators.lift((s, sub) -> createRequestContextSubscriber(sub)));
	}

	@Override
	public void destroy() throws Exception {
		Hooks.resetOnLastOperator(REQUEST_CONTEXT_OPERATOR_KEY);
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
				OAuth2AuthorizedClientProviderBuilder.withProvider()
						.authorizationCode()
						.refreshToken(configurer -> configurer.clockSkew(this.accessTokenExpiresSkew))
						.clientCredentials(this::updateClientCredentialsProvider)
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
		return spec -> {
			spec.attributes(attrs -> {
				populateDefaultRequestResponse(attrs);
				populateDefaultAuthentication(attrs);
				populateDefaultOAuth2AuthorizedClient(attrs);
			});
		};
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

	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		return Mono.just(request)
				.filter(req -> req.attribute(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME).isPresent())
				.switchIfEmpty(mergeRequestAttributesFromContext(request))
				.filter(req -> req.attribute(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME).isPresent())
				.flatMap(req -> authorizedClient(getOAuth2AuthorizedClient(req.attributes()), req))
				.map(authorizedClient -> bearer(request, authorizedClient))
				.flatMap(next::exchange)
				.switchIfEmpty(next.exchange(request));
	}

	private Mono<ClientRequest> mergeRequestAttributesFromContext(ClientRequest request) {
		return Mono.just(ClientRequest.from(request))
				.flatMap(builder -> Mono.subscriberContext()
						.map(ctx -> builder.attributes(attrs -> populateRequestAttributes(attrs, ctx))))
				.map(ClientRequest.Builder::build);
	}

	private void populateRequestAttributes(Map<String, Object> attrs, Context ctx) {
		if (ctx.hasKey(HTTP_SERVLET_REQUEST_ATTR_NAME)) {
			attrs.putIfAbsent(HTTP_SERVLET_REQUEST_ATTR_NAME, ctx.get(HTTP_SERVLET_REQUEST_ATTR_NAME));
		}
		if (ctx.hasKey(HTTP_SERVLET_RESPONSE_ATTR_NAME)) {
			attrs.putIfAbsent(HTTP_SERVLET_RESPONSE_ATTR_NAME, ctx.get(HTTP_SERVLET_RESPONSE_ATTR_NAME));
		}
		if (ctx.hasKey(AUTHENTICATION_ATTR_NAME)) {
			attrs.putIfAbsent(AUTHENTICATION_ATTR_NAME, ctx.get(AUTHENTICATION_ATTR_NAME));
		}
		populateDefaultOAuth2AuthorizedClient(attrs);
	}

	private void populateDefaultRequestResponse(Map<String, Object> attrs) {
		if (attrs.containsKey(HTTP_SERVLET_REQUEST_ATTR_NAME) &&
				attrs.containsKey(HTTP_SERVLET_RESPONSE_ATTR_NAME)) {
			return;
		}
		ServletRequestAttributes context = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		HttpServletRequest request = null;
		HttpServletResponse response = null;
		if (context != null) {
			request = context.getRequest();
			response = context.getResponse();
		}
		attrs.putIfAbsent(HTTP_SERVLET_REQUEST_ATTR_NAME, request);
		attrs.putIfAbsent(HTTP_SERVLET_RESPONSE_ATTR_NAME, response);
	}

	private void populateDefaultAuthentication(Map<String, Object> attrs) {
		if (attrs.containsKey(AUTHENTICATION_ATTR_NAME)) {
			return;
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		attrs.putIfAbsent(AUTHENTICATION_ATTR_NAME, authentication);
	}

	private void populateDefaultOAuth2AuthorizedClient(Map<String, Object> attrs) {
		if (this.authorizedClientManager == null ||
				attrs.containsKey(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME)) {
			return;
		}

		Authentication authentication = getAuthentication(attrs);
		String clientRegistrationId = getClientRegistrationId(attrs);
		if (clientRegistrationId == null) {
			clientRegistrationId = this.defaultClientRegistrationId;
		}
		if (clientRegistrationId == null
				&& this.defaultOAuth2AuthorizedClient
				&& authentication instanceof OAuth2AuthenticationToken) {
			clientRegistrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
		}
		if (clientRegistrationId != null) {
			HttpServletRequest request = getRequest(attrs);
			if (authentication == null) {
				authentication = ANONYMOUS_AUTHENTICATION;
			}
			OAuth2AuthorizeRequest authorizeRequest = new OAuth2AuthorizeRequest(
					clientRegistrationId, authentication, request, getResponse(attrs));
			OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
			oauth2AuthorizedClient(authorizedClient).accept(attrs);
		}
	}

	private Mono<OAuth2AuthorizedClient> authorizedClient(OAuth2AuthorizedClient authorizedClient, ClientRequest request) {
		if (this.authorizedClientManager == null) {
			return Mono.just(authorizedClient);
		}
		Map<String, Object> attrs = request.attributes();
		Authentication authentication = getAuthentication(attrs);
		if (authentication == null) {
			authentication = new PrincipalNameAuthentication(authorizedClient.getPrincipalName());
		}
		HttpServletRequest servletRequest = getRequest(attrs);
		HttpServletResponse servletResponse = getResponse(attrs);
		OAuth2ReauthorizeRequest reauthorizeRequest = new OAuth2ReauthorizeRequest(
				authorizedClient, authentication, servletRequest, servletResponse);
		return Mono.fromSupplier(() -> this.authorizedClientManager.reauthorize(reauthorizeRequest));
	}

	private ClientRequest bearer(ClientRequest request, OAuth2AuthorizedClient authorizedClient) {
		return ClientRequest.from(request)
					.headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
					.build();
	}

	private <T> CoreSubscriber<T> createRequestContextSubscriber(CoreSubscriber<T> delegate) {
		HttpServletRequest request = null;
		HttpServletResponse response = null;
		ServletRequestAttributes requestAttributes =
				(ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		if (requestAttributes != null) {
			request = requestAttributes.getRequest();
			response = requestAttributes.getResponse();
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return new RequestContextSubscriber<>(delegate, request, response, authentication);
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

	private static class PrincipalNameAuthentication implements Authentication {
		private final String principalName;

		private PrincipalNameAuthentication(String principalName) {
			Assert.hasText(principalName, "principalName cannot be empty");
			this.principalName = principalName;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			throw unsupported();
		}

		@Override
		public Object getCredentials() {
			throw unsupported();
		}

		@Override
		public Object getDetails() {
			throw unsupported();
		}

		@Override
		public Object getPrincipal() {
			return getName();
		}

		@Override
		public boolean isAuthenticated() {
			throw unsupported();
		}

		@Override
		public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
			throw unsupported();
		}

		@Override
		public String getName() {
			return this.principalName;
		}

		private UnsupportedOperationException unsupported() {
			return new UnsupportedOperationException("Not Supported");
		}
	}

	private static class RequestContextSubscriber<T> implements CoreSubscriber<T> {
		private static final String CONTEXT_DEFAULTED_ATTR_NAME = RequestContextSubscriber.class.getName().concat(".CONTEXT_DEFAULTED_ATTR_NAME");
		private final CoreSubscriber<T> delegate;
		private final HttpServletRequest request;
		private final HttpServletResponse response;
		private final Authentication authentication;

		private RequestContextSubscriber(CoreSubscriber<T> delegate,
											HttpServletRequest request,
											HttpServletResponse response,
											Authentication authentication) {
			this.delegate = delegate;
			this.request = request;
			this.response = response;
			this.authentication = authentication;
		}

		@Override
		public Context currentContext() {
			Context context = this.delegate.currentContext();
			if (context.hasKey(CONTEXT_DEFAULTED_ATTR_NAME)) {
				return context;
			}
			return Context.of(
					CONTEXT_DEFAULTED_ATTR_NAME, Boolean.TRUE,
					HTTP_SERVLET_REQUEST_ATTR_NAME, this.request,
					HTTP_SERVLET_RESPONSE_ATTR_NAME, this.response,
					AUTHENTICATION_ATTR_NAME, this.authentication);
		}

		@Override
		public void onSubscribe(Subscription s) {
			this.delegate.onSubscribe(s);
		}

		@Override
		public void onNext(T t) {
			this.delegate.onNext(t);
		}

		@Override
		public void onError(Throwable t) {
			this.delegate.onError(t);
		}

		@Override
		public void onComplete() {
			this.delegate.onComplete();
		}
	}
}
