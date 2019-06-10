/*
 * Copyright 2002-2018 the original author or authors.
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

import java.net.URI;
import java.util.Collections;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.util.Assert;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import static org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withJwkSetUri;

/**
 * Allows creating a {@link ReactiveJwtDecoder} from an
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Provider Configuration</a>.
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class ReactiveJwtDecoders {
	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";
	private static final String OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";
	private static final RestTemplate rest = new RestTemplate();
	private static final ParameterizedTypeReference<Map<String, Object>> typeReference =
			new ParameterizedTypeReference<Map<String, Object>>() {};

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
		Assert.hasText(oidcIssuerLocation, "oidcIssuerLocation cannot be empty");
		Map<String, Object> configuration = getConfiguration(oidcIssuerLocation, oidc(URI.create(oidcIssuerLocation)));
		return withProviderConfiguration(configuration, oidcIssuerLocation);
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
	 * @param issuer
	 * @return a {@link ReactiveJwtDecoder} that was initialized by one of the described endpoints
	 */
	public static ReactiveJwtDecoder fromIssuerLocation(String issuer) {
		Assert.hasText(issuer, "issuer cannot be empty");
		URI uri = URI.create(issuer);
		Map<String, Object> configuration = getConfiguration(issuer, oidc(uri), oidcRfc8414(uri), oauth(uri));
		return withProviderConfiguration(configuration, issuer);
	}

	private static URI oidc(URI issuer) {
		return UriComponentsBuilder.fromUri(issuer)
				.replacePath(issuer.getPath() + OIDC_METADATA_PATH).build(Collections.emptyMap());
	}

	private static URI oidcRfc8414(URI issuer) {
		return UriComponentsBuilder.fromUri(issuer)
				.replacePath(OIDC_METADATA_PATH + issuer.getPath()).build(Collections.emptyMap());
	}

	private static URI oauth(URI issuer) {
		return UriComponentsBuilder.fromUri(issuer)
				.replacePath(OAUTH_METADATA_PATH + issuer.getPath()).build(Collections.emptyMap());
	}

	private static Map<String, Object> getConfiguration(String issuer, URI... uris) {
		String errorMessage = "Unable to resolve the Configuration with the provided Issuer of " +
				"\"" + issuer + "\"";
		for (URI uri : uris) {
			try {
				RequestEntity<Void> request = RequestEntity.get(uri).build();
				ResponseEntity<Map<String, Object>> response = rest.exchange(request, typeReference);
				return response.getBody();
			} catch (RuntimeException e) {
				if (!(e instanceof HttpClientErrorException &&
						((HttpClientErrorException) e).getStatusCode().is4xxClientError())) {
					throw new IllegalArgumentException(errorMessage, e);
				}
				// else try another endpoint
			}
		}
		throw new IllegalArgumentException(errorMessage);
	}

	private static ReactiveJwtDecoder withProviderConfiguration(Map<String, Object> configuration, String issuer) {
		String metadataIssuer = "(unavailable)";
		if (configuration.containsKey("issuer")) {
			metadataIssuer = configuration.get("issuer").toString();
		}
		if (!issuer.equals(metadataIssuer)) {
			throw new IllegalStateException("The Issuer \"" + metadataIssuer + "\" provided in the configuration did not "
					+ "match the requested issuer \"" + issuer + "\"");
		}

		OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefaultWithIssuer(issuer);
		NimbusReactiveJwtDecoder jwtDecoder = withJwkSetUri(configuration.get("jwks_uri").toString()).build();
		jwtDecoder.setJwtValidator(jwtValidator);

		return jwtDecoder;
	}

	private ReactiveJwtDecoders() {}
}
