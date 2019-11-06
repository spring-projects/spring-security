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

package org.springframework.security.oauth2.client.oidc.web.server.logout;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import reactor.core.publisher.Mono;

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
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A reactive logout success handler for initiating OIDC logout through the user agent.
 *
 * @author Josh Cummings
 * @since 5.2
 * @see <a href="https://openid.net/specs/openid-connect-session-1_0.html#RPLogout">RP-Initiated Logout</a>
 * @see org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
 */
public class OidcClientInitiatedServerLogoutSuccessHandler
		implements ServerLogoutSuccessHandler {

	private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();
	private final RedirectServerLogoutSuccessHandler serverLogoutSuccessHandler
			= new RedirectServerLogoutSuccessHandler();
	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	private URI postLogoutRedirectUri;

	/**
	 * Constructs an {@link OidcClientInitiatedServerLogoutSuccessHandler} with the provided parameters
	 *
	 * @param clientRegistrationRepository The {@link ReactiveClientRegistrationRepository} to use to derive
	 * the end_session_endpoint value
	 */
	public OidcClientInitiatedServerLogoutSuccessHandler
			(ReactiveClientRegistrationRepository clientRegistrationRepository) {

		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
		return Mono.just(authentication)
				.filter(OAuth2AuthenticationToken.class::isInstance)
				.filter(token -> authentication.getPrincipal() instanceof OidcUser)
				.map(OAuth2AuthenticationToken.class::cast)
				.flatMap(this::endSessionEndpoint)
				.map(endSessionEndpoint -> endpointUri(endSessionEndpoint, authentication))
				.switchIfEmpty(this.serverLogoutSuccessHandler
						.onLogoutSuccess(exchange, authentication).then(Mono.empty()))
				.flatMap(endpointUri -> this.redirectStrategy.sendRedirect(exchange.getExchange(), endpointUri));
	}

	private Mono<URI> endSessionEndpoint(OAuth2AuthenticationToken token) {
		String registrationId = token.getAuthorizedClientRegistrationId();
		return this.clientRegistrationRepository.findByRegistrationId(registrationId)
				.map(ClientRegistration::getProviderDetails)
				.map(ClientRegistration.ProviderDetails::getConfigurationMetadata)
				.flatMap(configurationMetadata -> Mono.justOrEmpty(configurationMetadata.get("end_session_endpoint")))
				.map(Object::toString)
				.map(URI::create);
	}

	private URI endpointUri(URI endSessionEndpoint, Authentication authentication) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);
		builder.queryParam("id_token_hint", idToken(authentication));
		if (this.postLogoutRedirectUri != null) {
			builder.queryParam("post_logout_redirect_uri", this.postLogoutRedirectUri);
		}
		return builder.encode(StandardCharsets.UTF_8).build().toUri();
	}

	private String idToken(Authentication authentication) {
		return ((OidcUser) authentication.getPrincipal()).getIdToken().getTokenValue();
	}

	/**
	 * Set the post logout redirect uri to use
	 *
	 * @param postLogoutRedirectUri - A valid URL to which the OP should redirect after logging out the user
	 */
	public void setPostLogoutRedirectUri(URI postLogoutRedirectUri) {
		Assert.notNull(postLogoutRedirectUri, "postLogoutRedirectUri cannot be empty");
		this.postLogoutRedirectUri = postLogoutRedirectUri;
	}

	/**
	 * The URL to redirect to after successfully logging out when not originally an OIDC login
	 *
	 * @param logoutSuccessUrl the url to redirect to. Default is "/login?logout".
	 */
	public void setLogoutSuccessUrl(URI logoutSuccessUrl) {
		Assert.notNull(logoutSuccessUrl, "logoutSuccessUrl cannot be null");
		this.serverLogoutSuccessHandler.setLogoutSuccessUrl(logoutSuccessUrl);
	}
}
