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

package org.springframework.security.oauth2.client.web.server;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.endpoint.PkceParameterBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * The default implementation of {@link ServerOAuth2AuthorizationRequestResolver}.
 *
 * The {@link ClientRegistration#getRegistrationId()} is extracted from the request using the
 * {@link #DEFAULT_AUTHORIZATION_REQUEST_PATTERN}. The injected {@link ReactiveClientRegistrationRepository} is then
 * used to resolve the {@link ClientRegistration} and create the {@link OAuth2AuthorizationRequest}.
 *
 * @author Rob Winch
 * @since 5.1
 * @see ServerOAuth2AuthorizationRequestResolver
 * @see OAuth2AuthorizationRequestRedirectWebFilter
 * @see OAuth2AuthorizationRequest
 * @see PkceParameterBuilder
 */
public class DefaultServerOAuth2AuthorizationRequestResolver
		implements ServerOAuth2AuthorizationRequestResolver {

	/**
	 * The name of the path variable that contains the {@link ClientRegistration#getRegistrationId()}
	 */
	public static final String DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

	/**
	 * The default pattern used to resolve the {@link ClientRegistration#getRegistrationId()}
	 */
	public static final String DEFAULT_AUTHORIZATION_REQUEST_PATTERN = "/oauth2/authorization/{" + DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME + "}";

	private static final char PATH_DELIMITER = '/';

	private final ServerWebExchangeMatcher authorizationRequestMatcher;

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());

	private final BiConsumer<OAuth2AuthorizationRequest.Builder, ClientRegistration> pkceParameterBuilder = new PkceParameterBuilder();

	private BiConsumer<OAuth2AuthorizationRequest.Builder, ClientRegistration> authorizationRequestBuilder;

	/**
	 * Creates a new instance
	 * @param clientRegistrationRepository the repository to resolve the {@link ClientRegistration}
	 */
	public DefaultServerOAuth2AuthorizationRequestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository) {
		this(clientRegistrationRepository, new PathPatternParserServerWebExchangeMatcher(
				DEFAULT_AUTHORIZATION_REQUEST_PATTERN));
	}

	/**
	 * Creates a new instance
	 * @param clientRegistrationRepository the repository to resolve the {@link ClientRegistration}
	 * @param authorizationRequestMatcher the matcher that determines if the request is a match and extracts the
	 * {@link #DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME} from the path variables.
	 */
	public DefaultServerOAuth2AuthorizationRequestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository,
			ServerWebExchangeMatcher authorizationRequestMatcher) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizationRequestMatcher, "authorizationRequestMatcher cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizationRequestMatcher = authorizationRequestMatcher;
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
		return this.authorizationRequestMatcher.matches(exchange)
				.filter(matchResult -> matchResult.isMatch())
				.map(ServerWebExchangeMatcher.MatchResult::getVariables)
				.map(variables -> variables.get(DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME))
				.cast(String.class)
				.flatMap(clientRegistrationId -> resolve(exchange, clientRegistrationId));
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange,
			String clientRegistrationId) {
		return this.findByRegistrationId(exchange, clientRegistrationId)
			.map(clientRegistration -> authorizationRequest(exchange, clientRegistration));
	}

	/**
	 * Sets the {@link BiConsumer} that is ultimately supplied with the {@link OAuth2AuthorizationRequest.Builder} instance.
	 * This provides the ability for the {@code BiConsumer} to mutate the {@link OAuth2AuthorizationRequest} before it is built.
	 *
	 * @since 5.2
	 * @param authorizationRequestBuilder the {@link BiConsumer} that is supplied the {@code OAuth2AuthorizationRequest.Builder} instance
	 */
	public void setAuthorizationRequestBuilder(BiConsumer<OAuth2AuthorizationRequest.Builder, ClientRegistration> authorizationRequestBuilder) {
		Assert.notNull(authorizationRequestBuilder, "authorizationRequestBuilder cannot be null");
		this.authorizationRequestBuilder = authorizationRequestBuilder;
	}

	private Mono<ClientRegistration> findByRegistrationId(ServerWebExchange exchange, String clientRegistration) {
		return this.clientRegistrationRepository.findByRegistrationId(clientRegistration)
				.switchIfEmpty(Mono.error(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client registration id")));
	}

	private OAuth2AuthorizationRequest authorizationRequest(ServerWebExchange exchange,
			ClientRegistration clientRegistration) {

		OAuth2AuthorizationRequest.Builder builder;
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			builder = OAuth2AuthorizationRequest.authorizationCode();
		}
		else if (AuthorizationGrantType.IMPLICIT.equals(clientRegistration.getAuthorizationGrantType())) {
			builder = OAuth2AuthorizationRequest.implicit();
		}
		else {
			throw new IllegalArgumentException(
					"Invalid Authorization Grant Type (" + clientRegistration.getAuthorizationGrantType().getValue()
							+ ") for Client Registration with Id: " + clientRegistration.getRegistrationId());
		}

		String redirectUriStr = expandRedirectUri(exchange.getRequest(), clientRegistration);

		builder
				.clientId(clientRegistration.getClientId())
				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(redirectUriStr)
				.scopes(clientRegistration.getScopes())
				.state(this.stateGenerator.generateKey())
				.attributes(attrs -> attrs.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId()));

		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType()) &&
				ClientAuthenticationMethod.NONE.equals(clientRegistration.getClientAuthenticationMethod())) {
			// Add PKCE parameters for public clients
			this.pkceParameterBuilder.accept(builder, clientRegistration);
		}

		if (this.authorizationRequestBuilder != null) {
			this.authorizationRequestBuilder.accept(builder, clientRegistration);
		}

		return builder.build();
	}

	/**
	 * Expands the {@link ClientRegistration#getRedirectUriTemplate()} with following provided variables:<br/>
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
	 * Default redirectUriTemplate is: {@link org.springframework.security.config.oauth2.client}.CommonOAuth2Provider#DEFAULT_REDIRECT_URL
	 *
	 * @return expanded URI
	 */
	private static String expandRedirectUri(ServerHttpRequest request, ClientRegistration clientRegistration) {
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		UriComponents uriComponents = UriComponentsBuilder.fromUri(request.getURI())
				.replacePath(request.getPath().contextPath().value())
				.replaceQuery(null)
				.fragment(null)
				.build();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", scheme == null ? "" : scheme);
		String host = uriComponents.getHost();
		uriVariables.put("baseHost", host == null ? "" : host);
		// following logic is based on HierarchicalUriComponents#toUriString()
		int port = uriComponents.getPort();
		uriVariables.put("basePort", port == -1 ? "" : ":" + port);
		String path = uriComponents.getPath();
		if (StringUtils.hasLength(path)) {
			if (path.charAt(0) != PATH_DELIMITER) {
				path = PATH_DELIMITER + path;
			}
		}
		uriVariables.put("basePath", path == null ? "" : path);
		uriVariables.put("baseUrl", uriComponents.toUriString());

		String action = "";
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			action = "login";
		}
		uriVariables.put("action", action);

		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
				.buildAndExpand(uriVariables)
				.toUriString();
	}
}
