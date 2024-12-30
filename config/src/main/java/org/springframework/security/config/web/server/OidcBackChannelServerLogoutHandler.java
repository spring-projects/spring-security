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

package org.springframework.security.config.web.server;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.core.ResolvableType;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.EncoderHttpMessageWriter;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link ServerLogoutHandler} that locates the sessions associated with a given OIDC
 * Back-Channel Logout Token and invalidates each one.
 *
 * @author Josh Cummings
 * @since 6.4
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel Logout
 * Spec</a>
 */
public final class OidcBackChannelServerLogoutHandler implements ServerLogoutHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private final ReactiveOidcSessionRegistry sessionRegistry;

	private final HttpMessageWriter<OAuth2Error> errorHttpMessageConverter = new EncoderHttpMessageWriter<>(
			new OAuth2ErrorEncoder());

	private WebClient web = WebClient.create();

	private String logoutUri = "{baseUrl}/logout/connect/back-channel/{registrationId}";

	private String sessionCookieName = "SESSION";

	public OidcBackChannelServerLogoutHandler(ReactiveOidcSessionRegistry sessionRegistry) {
		this.sessionRegistry = sessionRegistry;
	}

	@Override
	public Mono<Void> logout(WebFilterExchange exchange, Authentication authentication) {
		if (!(authentication instanceof OidcBackChannelLogoutAuthentication token)) {
			return Mono.defer(() -> {
				if (this.logger.isDebugEnabled()) {
					String message = "Did not perform OIDC Back-Channel Logout since authentication [%s] was of the wrong type";
					this.logger.debug(String.format(message, authentication.getClass().getSimpleName()));
				}
				return Mono.empty();
			});
		}
		AtomicInteger totalCount = new AtomicInteger(0);
		AtomicInteger invalidatedCount = new AtomicInteger(0);
		return this.sessionRegistry.removeSessionInformation(token.getPrincipal()).concatMap((session) -> {
			totalCount.incrementAndGet();
			return eachLogout(exchange, session, token).flatMap((response) -> {
				invalidatedCount.incrementAndGet();
				return Mono.empty();
			}).onErrorResume((ex) -> {
				this.logger.debug("Failed to invalidate session", ex);
				return this.sessionRegistry.saveSessionInformation(session).then(Mono.just(ex.getMessage()));
			});
		}).collectList().flatMap((list) -> {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(String.format("Invalidated %d out of %d sessions", invalidatedCount.intValue(),
						totalCount.intValue()));
			}
			if (!list.isEmpty()) {
				return handleLogoutFailure(exchange.getExchange(), oauth2Error(list));
			}
			else {
				return Mono.empty();
			}
		});
	}

	private Mono<ResponseEntity<Void>> eachLogout(WebFilterExchange exchange, OidcSessionInformation session,
			OidcBackChannelLogoutAuthentication token) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.COOKIE, this.sessionCookieName + "=" + session.getSessionId());
		for (Map.Entry<String, String> credential : session.getAuthorities().entrySet()) {
			headers.add(credential.getKey(), credential.getValue());
		}
		String logout = computeLogoutEndpoint(exchange.getExchange().getRequest(), token);
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("logout_token", token.getPrincipal().getTokenValue());
		body.add("_spring_security_internal_logout", "true");
		return this.web.post()
			.uri(logout)
			.headers((h) -> h.putAll(headers))
			.body(BodyInserters.fromFormData(body))
			.retrieve()
			.toBodilessEntity();
	}

	String computeLogoutEndpoint(ServerHttpRequest request, OidcBackChannelLogoutAuthentication token) {
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

		String registrationId = token.getClientRegistration().getRegistrationId();
		uriVariables.put("registrationId", registrationId);

		return UriComponentsBuilder.fromUriString(this.logoutUri)
				.buildAndExpand(uriVariables)
				.toUriString();
		// @formatter:on
	}

	private OAuth2Error oauth2Error(Collection<?> errors) {
		return new OAuth2Error("partial_logout", "not all sessions were terminated: " + errors,
				"https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
	}

	private Mono<Void> handleLogoutFailure(ServerWebExchange exchange, OAuth2Error error) {
		exchange.getResponse().setRawStatusCode(HttpServletResponse.SC_BAD_REQUEST);
		return this.errorHttpMessageConverter.write(Mono.just(error), ResolvableType.forClass(Object.class),
				ResolvableType.forClass(Object.class), MediaType.APPLICATION_JSON, exchange.getRequest(),
				exchange.getResponse(), Collections.emptyMap());
	}

	/**
	 * Use this logout URI for performing per-session logout. Defaults to {@code /logout}
	 * since that is the default URI for
	 * {@link org.springframework.security.web.authentication.logout.LogoutFilter}.
	 * @param logoutUri the URI to use
	 */
	public void setLogoutUri(String logoutUri) {
		Assert.hasText(logoutUri, "logoutUri cannot be empty");
		this.logoutUri = logoutUri;
	}

	/**
	 * Use this cookie name for the session identifier. Defaults to {@code JSESSIONID}.
	 *
	 * <p>
	 * Note that if you are using Spring Session, this likely needs to change to SESSION.
	 * @param sessionCookieName the cookie name to use
	 */
	public void setSessionCookieName(String sessionCookieName) {
		Assert.hasText(sessionCookieName, "clientSessionCookieName cannot be empty");
		this.sessionCookieName = sessionCookieName;
	}

}
