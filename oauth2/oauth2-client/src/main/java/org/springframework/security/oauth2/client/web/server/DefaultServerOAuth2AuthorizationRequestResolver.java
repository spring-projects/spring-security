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

package org.springframework.security.oauth2.client.web.server;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * The default implementation of {@link ServerOAuth2AuthorizationRequestResolver}.
 *
 * The {@link ClientRegistration#getRegistrationId()} is extracted from the request using
 * the {@link #DEFAULT_AUTHORIZATION_REQUEST_PATTERN}. The injected
 * {@link ReactiveClientRegistrationRepository} is then used to resolve the
 * {@link ClientRegistration} and create the {@link OAuth2AuthorizationRequest}.
 *
 * @author Rob Winch
 * @author Mark Heckler
 * @author Joe Grandja
 * @since 5.1
 */
public class DefaultServerOAuth2AuthorizationRequestResolver implements ServerOAuth2AuthorizationRequestResolver {

	/**
	 * The name of the path variable that contains the
	 * {@link ClientRegistration#getRegistrationId()}
	 */
	public static final String DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

	/**
	 * The default pattern used to resolve the
	 * {@link ClientRegistration#getRegistrationId()}
	 */
	public static final String DEFAULT_AUTHORIZATION_REQUEST_PATTERN = "/oauth2/authorization/{"
			+ DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME + "}";

	private static final char PATH_DELIMITER = '/';

	private static final StringKeyGenerator DEFAULT_STATE_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder());

	private static final StringKeyGenerator DEFAULT_SECURE_KEY_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	private static final Consumer<OAuth2AuthorizationRequest.Builder> DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
			.withPkce();

	private final ServerWebExchangeMatcher authorizationRequestMatcher;

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer = (customizer) -> {
	};

	/**
	 * Creates a new instance
	 * @param clientRegistrationRepository the repository to resolve the
	 * {@link ClientRegistration}
	 */
	public DefaultServerOAuth2AuthorizationRequestResolver(
			ReactiveClientRegistrationRepository clientRegistrationRepository) {
		this(clientRegistrationRepository,
				new PathPatternParserServerWebExchangeMatcher(DEFAULT_AUTHORIZATION_REQUEST_PATTERN));
	}

	/**
	 * Creates a new instance
	 * @param clientRegistrationRepository the repository to resolve the
	 * {@link ClientRegistration}
	 * @param authorizationRequestMatcher the matcher that determines if the request is a
	 * match and extracts the {@link #DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME} from the
	 * path variables.
	 */
	public DefaultServerOAuth2AuthorizationRequestResolver(
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			ServerWebExchangeMatcher authorizationRequestMatcher) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizationRequestMatcher, "authorizationRequestMatcher cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizationRequestMatcher = authorizationRequestMatcher;
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
		// @formatter:off
		return this.authorizationRequestMatcher
				.matches(exchange)
				.filter((matchResult) -> matchResult.isMatch())
				.map(ServerWebExchangeMatcher.MatchResult::getVariables)
				.map((variables) -> variables.get(DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME))
				.cast(String.class)
				.flatMap((clientRegistrationId) -> resolve(exchange, clientRegistrationId));
		// @formatter:on
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId) {
		return findByRegistrationId(exchange, clientRegistrationId)
				.map((clientRegistration) -> authorizationRequest(exchange, clientRegistration));
	}

	/**
	 * Sets the {@code Consumer} to be provided the
	 * {@link OAuth2AuthorizationRequest.Builder} allowing for further customizations.
	 * @param authorizationRequestCustomizer the {@code Consumer} to be provided the
	 * {@link OAuth2AuthorizationRequest.Builder}
	 * @since 5.3
	 * @see OAuth2AuthorizationRequestCustomizers
	 */
	public final void setAuthorizationRequestCustomizer(
			Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer) {
		Assert.notNull(authorizationRequestCustomizer, "authorizationRequestCustomizer cannot be null");
		this.authorizationRequestCustomizer = authorizationRequestCustomizer;
	}

	private Mono<ClientRegistration> findByRegistrationId(ServerWebExchange exchange, String clientRegistration) {
		// @formatter:off
		return this.clientRegistrationRepository.findByRegistrationId(clientRegistration)
				.switchIfEmpty(Mono.error(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client registration id")));
		// @formatter:on
	}

	private OAuth2AuthorizationRequest authorizationRequest(ServerWebExchange exchange,
			ClientRegistration clientRegistration) {
		OAuth2AuthorizationRequest.Builder builder = getBuilder(clientRegistration);
		String redirectUriStr = expandRedirectUri(exchange.getRequest(), clientRegistration);
		// @formatter:off
		builder.clientId(clientRegistration.getClientId())
				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(redirectUriStr)
				.scopes(clientRegistration.getScopes())
				.state(DEFAULT_STATE_GENERATOR.generateKey());
		// @formatter:on

		this.authorizationRequestCustomizer.accept(builder);

		return builder.build();
	}

	private OAuth2AuthorizationRequest.Builder getBuilder(ClientRegistration clientRegistration) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			// @formatter:off
			OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest.authorizationCode()
					.attributes((attrs) ->
							attrs.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId()));
			// @formatter:on
			if (!CollectionUtils.isEmpty(clientRegistration.getScopes())
					&& clientRegistration.getScopes().contains(OidcScopes.OPENID)) {
				// Section 3.1.2.1 Authentication Request -
				// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
				// scope
				// REQUIRED. OpenID Connect requests MUST contain the "openid" scope
				// value.
				applyNonce(builder);
			}
			if (ClientAuthenticationMethod.NONE.equals(clientRegistration.getClientAuthenticationMethod())) {
				DEFAULT_PKCE_APPLIER.accept(builder);
			}
			return builder;
		}
		throw new IllegalArgumentException(
				"Invalid Authorization Grant Type (" + clientRegistration.getAuthorizationGrantType().getValue()
						+ ") for Client Registration with Id: " + clientRegistration.getRegistrationId());
	}

	/**
	 * Expands the {@link ClientRegistration#getRedirectUri()} with following provided
	 * variables:<br/>
	 * - baseUrl (e.g. https://localhost/app) <br/>
	 * - baseScheme (e.g. https) <br/>
	 * - baseHost (e.g. localhost) <br/>
	 * - basePort (e.g. :8080) <br/>
	 * - basePath (e.g. /app) <br/>
	 * - registrationId (e.g. google) <br/>
	 * - action (e.g. login) <br/>
	 * <p/>
	 * Null variables are provided as empty strings.
	 * <p/>
	 * Default redirectUri is:
	 * {@code org.springframework.security.config.oauth2.client.CommonOAuth2Provider#DEFAULT_REDIRECT_URL}
	 * @return expanded URI
	 */
	private static String expandRedirectUri(ServerHttpRequest request, ClientRegistration clientRegistration) {
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());
		// @formatter:off
		UriComponents uriComponents = UriComponentsBuilder.fromUri(request.getURI())
				.replacePath(request.getPath().contextPath().value())
				.replaceQuery(null)
				.fragment(null)
				.build();
		// @formatter:on
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
		String host = uriComponents.getHost();
		uriVariables.put("baseHost", (host != null) ? host : "");
		// following logic is based on HierarchicalUriComponents#toUriString()
		int port = uriComponents.getPort();
		uriVariables.put("basePort", (port == -1) ? "" : ":" + port);
		String path = uriComponents.getPath();
		if (StringUtils.hasLength(path)) {
			if (path.charAt(0) != PATH_DELIMITER) {
				path = PATH_DELIMITER + path;
			}
		}
		uriVariables.put("basePath", (path != null) ? path : "");
		uriVariables.put("baseUrl", uriComponents.toUriString());
		String action = "";
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			action = "login";
		}
		uriVariables.put("action", action);
		// @formatter:off
		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUri())
				.buildAndExpand(uriVariables)
				.toUriString();
		// @formatter:on
	}

	/**
	 * Creates nonce and its hash for use in OpenID Connect 1.0 Authentication Requests.
	 * @param builder where the {@link OidcParameterNames#NONCE} and hash is stored for
	 * the authentication request
	 *
	 * @since 5.2
	 * @see <a target="_blank" href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">3.1.2.1.
	 * Authentication Request</a>
	 */
	private static void applyNonce(OAuth2AuthorizationRequest.Builder builder) {
		try {
			String nonce = DEFAULT_SECURE_KEY_GENERATOR.generateKey();
			String nonceHash = createHash(nonce);
			builder.attributes((attrs) -> attrs.put(OidcParameterNames.NONCE, nonce));
			builder.additionalParameters((params) -> params.put(OidcParameterNames.NONCE, nonceHash));
		}
		catch (NoSuchAlgorithmException ex) {
		}
	}

	private static String createHash(String value) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
