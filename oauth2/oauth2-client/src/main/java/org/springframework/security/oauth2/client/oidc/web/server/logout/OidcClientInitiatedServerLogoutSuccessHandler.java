/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.web.server.logout;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import reactor.core.publisher.Mono;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A reactive logout success handler for initiating OIDC logout through the user agent.
 *
 * @author Josh Cummings
 * @since 5.2
 * @see <a href=
 * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a>
 * @see org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
 */
public class OidcClientInitiatedServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {

	private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

	private final RedirectServerLogoutSuccessHandler serverLogoutSuccessHandler = new RedirectServerLogoutSuccessHandler();

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	private String postLogoutRedirectUri;

	/**
	 * Constructs an {@link OidcClientInitiatedServerLogoutSuccessHandler} with the
	 * provided parameters
	 * @param clientRegistrationRepository The
	 * {@link ReactiveClientRegistrationRepository} to use to derive the
	 * end_session_endpoint value
	 */
	public OidcClientInitiatedServerLogoutSuccessHandler(
			ReactiveClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
		// @formatter:off
		return Mono.just(authentication)
				.filter(OAuth2AuthenticationToken.class::isInstance)
				.filter((token) -> authentication.getPrincipal() instanceof OidcUser)
				.map(OAuth2AuthenticationToken.class::cast)
				.map(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId)
				.flatMap(this.clientRegistrationRepository::findByRegistrationId)
				.flatMap((clientRegistration) -> {
					URI endSessionEndpoint = endSessionEndpoint(clientRegistration);
					if (endSessionEndpoint == null) {
						return Mono.empty();
					}
					String idToken = idToken(authentication);
					String postLogoutRedirectUri = postLogoutRedirectUri(exchange.getExchange().getRequest(), clientRegistration);
					return Mono.just(endpointUri(endSessionEndpoint, idToken, postLogoutRedirectUri));
				})
				.switchIfEmpty(
						this.serverLogoutSuccessHandler.onLogoutSuccess(exchange, authentication).then(Mono.empty())
				)
				.flatMap((endpointUri) -> this.redirectStrategy.sendRedirect(exchange.getExchange(), URI.create(endpointUri)));
		// @formatter:on
	}

	private URI endSessionEndpoint(ClientRegistration clientRegistration) {
		if (clientRegistration != null) {
			Object endSessionEndpoint = clientRegistration.getProviderDetails().getConfigurationMetadata()
					.get("end_session_endpoint");
			if (endSessionEndpoint != null) {
				return URI.create(endSessionEndpoint.toString());
			}
		}
		return null;
	}

	private String endpointUri(URI endSessionEndpoint, String idToken, String postLogoutRedirectUri) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);
		builder.queryParam("id_token_hint", idToken);
		if (postLogoutRedirectUri != null) {
			builder.queryParam("post_logout_redirect_uri", postLogoutRedirectUri);
		}
		return builder.encode(StandardCharsets.UTF_8).build().toUriString();
	}

	private String idToken(Authentication authentication) {
		return ((OidcUser) authentication.getPrincipal()).getIdToken().getTokenValue();
	}

	private String postLogoutRedirectUri(ServerHttpRequest request, ClientRegistration clientRegistration) {
		if (this.postLogoutRedirectUri == null) {
			return null;
		}
		// @formatter:off
		UriComponents uriComponents = UriComponentsBuilder.fromUri(request.getURI())
				.replacePath(request.getPath().contextPath().value())
				.replaceQuery(null)
				.fragment(null)
				.build();

		Map<String, String> uriVariables = new HashMap<>();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
		uriVariables.put("baseUrl", uriComponents.toUriString());

		String host = uriComponents.getHost();
		uriVariables.put("baseHost", (host != null) ? host : "");

		String path = uriComponents.getPath();
		uriVariables.put("basePath", (path != null) ? path : "");

		int port = uriComponents.getPort();
		uriVariables.put("basePort", (port == -1) ? "" : ":" + port);

		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		return UriComponentsBuilder.fromUriString(this.postLogoutRedirectUri)
				.buildAndExpand(uriVariables)
				.toUriString();
		// @formatter:on
	}

	/**
	 * Set the post logout redirect uri template.
	 *
	 * <br />
	 * The supported uri template variables are: {@code {baseScheme}}, {@code {baseHost}},
	 * {@code {basePort}} and {@code {basePath}}.
	 *
	 * <br />
	 * <b>NOTE:</b> {@code {baseUrl}} is also supported, which is the same as
	 * {@code "{baseScheme}://{baseHost}{basePort}{basePath}"}
	 *
	 * <pre>
	 * 	handler.setPostLogoutRedirectUri("{baseUrl}");
	 * </pre>
	 *
	 * will make so that {@code post_logout_redirect_uri} will be set to the base url for
	 * the client application.
	 * @param postLogoutRedirectUri - A template for creating the
	 * {@code post_logout_redirect_uri} query parameter
	 * @since 5.3
	 */
	public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
		Assert.notNull(postLogoutRedirectUri, "postLogoutRedirectUri cannot be null");
		this.postLogoutRedirectUri = postLogoutRedirectUri;
	}

	/**
	 * The URL to redirect to after successfully logging out when not originally an OIDC
	 * login
	 * @param logoutSuccessUrl the url to redirect to. Default is "/login?logout".
	 */
	public void setLogoutSuccessUrl(URI logoutSuccessUrl) {
		Assert.notNull(logoutSuccessUrl, "logoutSuccessUrl cannot be null");
		this.serverLogoutSuccessHandler.setLogoutSuccessUrl(logoutSuccessUrl);
	}

}
