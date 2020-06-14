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
package org.springframework.security.oauth2.jwt;

import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withJwkSetUri;

/**
 * Allows creating a {@link ReactiveJwtDecoder} from an
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Provider Configuration</a> or
 * <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server Metadata Request</a> based on provided
 * issuer and method invoked.
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class ReactiveJwtDecoders {

	/**
	 * Creates a {@link ReactiveJwtDecoder} using the provided
	 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> by making an
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> and using the values in the
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the {@link ReactiveJwtDecoder}.
	 *
	 * @param oidcIssuerLocation the <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link ReactiveJwtDecoder} that was initialized by the OpenID Provider Configuration.
	 */
	public static ReactiveJwtDecoder fromOidcIssuerLocation(String oidcIssuerLocation) {
		return fromOidcIssuerLocation(oidcIssuerLocation, null, null);
	}

	/**
	 * Creates a {@link ReactiveJwtDecoder} using the provided
	 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> by making an
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> and using the values in the
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the {@link ReactiveJwtDecoder}.
	 *
	 * @param oidcIssuerLocation the <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @param webClient used as http-client (if not specified default http-client is used) for reactive operations
	 * @param restOperations used as http-client (if not specified default http-client is used)
	 * @return a {@link ReactiveJwtDecoder} that was initialized by the OpenID Provider Configuration.
	 */
	public static ReactiveJwtDecoder fromOidcIssuerLocation(String oidcIssuerLocation,
			RestOperations restOperations,
			WebClient webClient) {
		Assert.hasText(oidcIssuerLocation, "oidcIssuerLocation cannot be empty");
		Map<String, Object> configuration = JwtDecoderProviderConfigurationUtils.getConfigurationForOidcIssuerLocation(oidcIssuerLocation, restOperations);
		return withProviderConfiguration(configuration, oidcIssuerLocation, webClient);
	}

	/**
	 * Creates a {@link ReactiveJwtDecoder} using the provided
	 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> by querying
	 * three different discovery endpoints serially, using the values in the first successful response to
	 * initialize. If an endpoint returns anything other than a 200 or a 4xx, the method will exit without
	 * attempting subsequent endpoints.
	 *
	 * The three endpoints are computed as follows, given that the {@code issuer} is composed of a {@code host}
	 * and a {@code path}:
	 *
	 * <ol>
	 * 	<li>
	 * 	   {@code host/.well-known/openid-configuration/path}, as defined in
	 * 	   <a href="https://tools.ietf.org/html/rfc8414#section-5">RFC 8414's Compatibility Notes</a>.
	 *  </li>
	 *  <li>
	 *      {@code issuer/.well-known/openid-configuration}, as defined in
	 *  	<a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">
	 * 	    OpenID Provider Configuration</a>.
	 *  </li>
	 *  <li>
	 *      {@code host/.well-known/oauth-authorization-server/path}, as defined in
	 *  	<a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server Metadata Request</a>.
	 *  </li>
	 * </ol>
	 *
	 * Note that the second endpoint is the equivalent of calling
	 * {@link ReactiveJwtDecoders#fromOidcIssuerLocation(String)}
	 *
	 * @param issuer the <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link ReactiveJwtDecoder} that was initialized by one of the described endpoints
	 */
	public static ReactiveJwtDecoder fromIssuerLocation(String issuer) {
		return fromIssuerLocation(issuer, null, null);
	}

	/**
	 * Creates a {@link ReactiveJwtDecoder} using the provided
	 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> by querying
	 * three different discovery endpoints serially, using the values in the first successful response to
	 * initialize. If an endpoint returns anything other than a 200 or a 4xx, the method will exit without
	 * attempting subsequent endpoints.
	 *
	 * The three endpoints are computed as follows, given that the {@code issuer} is composed of a {@code host}
	 * and a {@code path}:
	 *
	 * <ol>
	 * 	<li>
	 * 	   {@code host/.well-known/openid-configuration/path}, as defined in
	 * 	   <a href="https://tools.ietf.org/html/rfc8414#section-5">RFC 8414's Compatibility Notes</a>.
	 *  </li>
	 *  <li>
	 *      {@code issuer/.well-known/openid-configuration}, as defined in
	 *  	<a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">
	 * 	    OpenID Provider Configuration</a>.
	 *  </li>
	 *  <li>
	 *      {@code host/.well-known/oauth-authorization-server/path}, as defined in
	 *  	<a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server Metadata Request</a>.
	 *  </li>
	 * </ol>
	 *
	 * Note that the second endpoint is the equivalent of calling
	 * {@link ReactiveJwtDecoders#fromOidcIssuerLocation(String)}
	 *
	 * @param issuer the <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @param webClient used as http-client (if not specified default http-client is used) for reactive operations
	 * @param restOperations used as http-client (if not specified default http-client is used)
	 * @return a {@link ReactiveJwtDecoder} that was initialized by one of the described endpoints
	 */
	public static ReactiveJwtDecoder fromIssuerLocation(String issuer,
			RestOperations restOperations,
			WebClient webClient) {
		Assert.hasText(issuer, "issuer cannot be empty");
		Map<String, Object> configuration = JwtDecoderProviderConfigurationUtils.getConfigurationForIssuerLocation(issuer, restOperations);
		return withProviderConfiguration(configuration, issuer, webClient);
	}

	/**
	 * Build {@link ReactiveJwtDecoder} from
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID Provider
	 * Configuration Response</a> and <a href="https://tools.ietf.org/html/rfc8414#section-3.2">Authorization Server Metadata
	 * Response</a>.
	 *
	 * @param configuration the configuration values
	 * @param issuer        the <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @param webClient used as http-client (if not specified default http-client is used) for reactive operations
	 * @return {@link ReactiveJwtDecoder}
	 */
	private static ReactiveJwtDecoder withProviderConfiguration(Map<String, Object> configuration,
			String issuer,
			WebClient webClient) {
		JwtDecoderProviderConfigurationUtils.validateIssuer(configuration, issuer);
		OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefaultWithIssuer(issuer);
		final NimbusReactiveJwtDecoder.JwkSetUriReactiveJwtDecoderBuilder builder =
				withJwkSetUri(configuration.get("jwks_uri").toString());
		if (webClient != null) {
			builder.webClient(webClient);
		}
		NimbusReactiveJwtDecoder jwtDecoder = builder.build();
		jwtDecoder.setJwtValidator(jwtValidator);

		return jwtDecoder;
	}

	private ReactiveJwtDecoders() {}
}
