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

package org.springframework.security.oauth2.client.web.server;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

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
 *  delegate it to the {@link ReactiveAuthenticationManager} to authenticate.
 * </li>
 * <li>
 *  Upon a successful authentication, an {@link OAuth2AuthorizedClient Authorized Client} is created by associating the
 *  {@link OAuth2AuthorizationCodeAuthenticationToken#getClientRegistration() client} to the
 *  {@link OAuth2AuthorizationCodeAuthenticationToken#getAccessToken() access token} and current {@code Principal}
 *  and saving it via the {@link ServerOAuth2AuthorizedClientRepository}.
 * </li>
 * </ul>
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeReactiveAuthenticationManager
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationResponse
 * @see AuthorizationRequestRepository
 * @see org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter
 * @see ReactiveClientRegistrationRepository
 * @see OAuth2AuthorizedClient
 * @see ServerOAuth2AuthorizedClientRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public class OAuth2AuthorizationCodeGrantWebFilter implements WebFilter {
	private final ReactiveAuthenticationManager authenticationManager;

	private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
			new WebSessionOAuth2ServerAuthorizationRequestRepository();

	private ServerAuthenticationSuccessHandler authenticationSuccessHandler;

	private ServerAuthenticationConverter authenticationConverter;

	private boolean defaultAuthenticationConverter;

	private ServerAuthenticationFailureHandler authenticationFailureHandler;

	private ServerWebExchangeMatcher requiresAuthenticationMatcher;

	private AnonymousAuthenticationToken anonymousToken = new AnonymousAuthenticationToken("key", "anonymous",
					AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	public OAuth2AuthorizationCodeGrantWebFilter(
			ReactiveAuthenticationManager authenticationManager,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.authenticationManager = authenticationManager;
		this.authorizedClientRepository = authorizedClientRepository;
		this.requiresAuthenticationMatcher = this::matchesAuthorizationResponse;
		ServerOAuth2AuthorizationCodeAuthenticationTokenConverter authenticationConverter =
				new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(clientRegistrationRepository);
		authenticationConverter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
		this.authenticationConverter = authenticationConverter;
		this.defaultAuthenticationConverter = true;
		this.authenticationSuccessHandler = new RedirectServerAuthenticationSuccessHandler();
		this.authenticationFailureHandler = (webFilterExchange, exception) -> Mono.error(exception);
	}

	public OAuth2AuthorizationCodeGrantWebFilter(
			ReactiveAuthenticationManager authenticationManager,
			ServerAuthenticationConverter authenticationConverter,
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.authenticationManager = authenticationManager;
		this.authorizedClientRepository = authorizedClientRepository;
		this.requiresAuthenticationMatcher = this::matchesAuthorizationResponse;
		this.authenticationConverter = authenticationConverter;
		this.authenticationSuccessHandler = new RedirectServerAuthenticationSuccessHandler();
		this.authenticationFailureHandler = (webFilterExchange, exception) -> Mono.error(exception);
	}

	/**
	 * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
	 * The default is {@link WebSessionOAuth2ServerAuthorizationRequestRepository}.
	 *
	 * @since 5.2
	 * @param authorizationRequestRepository the repository used for storing {@link OAuth2AuthorizationRequest}'s
	 */
	public final void setAuthorizationRequestRepository(
			ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
		updateDefaultAuthenticationConverter();
	}

	private void updateDefaultAuthenticationConverter() {
		if (this.defaultAuthenticationConverter) {
			((ServerOAuth2AuthorizationCodeAuthenticationTokenConverter) this.authenticationConverter)
					.setAuthorizationRequestRepository(this.authorizationRequestRepository);
		}
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.requiresAuthenticationMatcher.matches(exchange)
				.filter(ServerWebExchangeMatcher.MatchResult::isMatch)
				.flatMap(matchResult -> this.authenticationConverter.convert(exchange))
				.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
				.flatMap(token -> authenticate(exchange, chain, token));
	}

	private Mono<Void> authenticate(ServerWebExchange exchange,
			WebFilterChain chain, Authentication token) {
		WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, chain);
		return this.authenticationManager.authenticate(token)
				.switchIfEmpty(Mono.defer(() -> Mono.error(new IllegalStateException("No provider found for " + token.getClass()))))
				.flatMap(authentication -> onAuthenticationSuccess(authentication, webFilterExchange))
				.onErrorResume(AuthenticationException.class, e -> this.authenticationFailureHandler
						.onAuthenticationFailure(webFilterExchange, e));
	}

	private Mono<Void> onAuthenticationSuccess(Authentication authentication, WebFilterExchange webFilterExchange) {
		OAuth2AuthorizationCodeAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeAuthenticationToken) authentication;
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				authenticationResult.getClientRegistration(),
				authenticationResult.getName(),
				authenticationResult.getAccessToken(),
				authenticationResult.getRefreshToken());
		return this.authenticationSuccessHandler
					.onAuthenticationSuccess(webFilterExchange, authentication)
					.then(ReactiveSecurityContextHolder.getContext()
							.map(SecurityContext::getAuthentication)
							.defaultIfEmpty(this.anonymousToken)
							.flatMap(principal -> this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, principal, webFilterExchange.getExchange()))
					);
	}

	private Mono<ServerWebExchangeMatcher.MatchResult> matchesAuthorizationResponse(ServerWebExchange exchange) {
		return Mono.just(exchange)
				.filter(exch -> OAuth2AuthorizationResponseUtils.isAuthorizationResponse(exch.getRequest().getQueryParams()))
				.flatMap(exch -> this.authorizationRequestRepository.loadAuthorizationRequest(exchange)
						.flatMap(authorizationRequest ->
								matchesRedirectUri(exch.getRequest().getURI(), authorizationRequest.getRedirectUri())))
				.switchIfEmpty(ServerWebExchangeMatcher.MatchResult.notMatch());
	}

	private static Mono<ServerWebExchangeMatcher.MatchResult> matchesRedirectUri(
			URI authorizationResponseUri, String authorizationRequestRedirectUri) {
		UriComponents requestUri = UriComponentsBuilder.fromUri(authorizationResponseUri).build();
		UriComponents redirectUri = UriComponentsBuilder.fromUriString(authorizationRequestRedirectUri).build();
		Set<Map.Entry<String, List<String>>> requestUriParameters =
				new LinkedHashSet<>(requestUri.getQueryParams().entrySet());
		Set<Map.Entry<String, List<String>>> redirectUriParameters =
				new LinkedHashSet<>(redirectUri.getQueryParams().entrySet());
		// Remove the additional request parameters (if any) from the authorization response (request)
		// before doing an exact comparison with the authorizationRequest.getRedirectUri() parameters (if any)
		requestUriParameters.retainAll(redirectUriParameters);

		if (Objects.equals(requestUri.getScheme(), redirectUri.getScheme()) &&
				Objects.equals(requestUri.getUserInfo(), redirectUri.getUserInfo()) &&
				Objects.equals(requestUri.getHost(), redirectUri.getHost()) &&
				Objects.equals(requestUri.getPort(), redirectUri.getPort()) &&
				Objects.equals(requestUri.getPath(), redirectUri.getPath()) &&
				Objects.equals(requestUriParameters.toString(), redirectUriParameters.toString())) {
			return ServerWebExchangeMatcher.MatchResult.match();
		}
		return ServerWebExchangeMatcher.MatchResult.notMatch();
	}
}
