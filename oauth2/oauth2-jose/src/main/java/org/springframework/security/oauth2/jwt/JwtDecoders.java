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

import static org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withJwkSetUri;

import java.net.URI;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Allows creating a {@link JwtDecoder} from an
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Provider Configuration</a> or
 * <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server Metadata Request</a> based on provided
 * issuer and method invoked.
 *
 * @author Josh Cummings
 * @author Rafiullah Hamedy
 * @since 5.1
 */
public final class JwtDecoders {
	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";
	private static final String OAUTH2_METADATA_PATH = "/.well-known/oauth-authorization-server";

	/**
	 * Creates a {@link JwtDecoder} using the provided
	 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> by making an
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> and using the values in the
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the {@link JwtDecoder}.
	 *
	 * @param oidcIssuerLocation the <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link JwtDecoder} that was initialized by the OpenID Provider Configuration.
	 */
	public static JwtDecoder fromOidcIssuerLocation(String oidcIssuerLocation) {
		Map<String, Object> configuration = getIssuerConfiguration(oidcIssuerLocation, OIDC_METADATA_PATH);
		return withProviderConfiguration(configuration, oidcIssuerLocation);
	}

	/**
	 * Creates a {@link JwtDecoder} using the provided issuer by querying configuration metadata endpoints for
	 * OpenID (including fallback to legacy) and OAuth2 in order.
	 *
	 * <ol>
	 * <li>
	 * <strong>{host}/.well-known/openid-configuration/issuer1</strong> - OpenID Provider Configuration Request based on
	 * <a href="https://tools.ietf.org/html/rfc8414#section-5">Section 5</a> of <a href="https://tools.ietf.org/html/rfc8414">
	 * RFC 8414 Specification</a>
	 * </li>
	 * <li>
	 * <strong>{host}/issuer1/.well-known/openid-configuration</strong> - OpenID v1 Discovery endpoint based on
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> with backward compatibility highlighted on <a href="https://tools.ietf.org/html/rfc8414#section-5">
	 * Section 5</a> of RF 8414
	 * </li>
	 * <li>
	 * <strong>{host}/.well-known/oauth-authorization-server/issuer1</strong> - OAuth2 Authorization Server Metadata based on
	 * <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Section 3.1</a> of RFC 8414
	 * </li>
	 * </ol>
	 *
	 * @param issuer
	 * @return a {@link JwtDecoder} that is initialized using
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">
	 * OpenID Provider Configuration Response</a> or <a href="https://tools.ietf.org/html/rfc8414#section-3.2">
	 * Authorization Server Metadata Response</a> depending on provided issuer
	 */
	public static JwtDecoder fromIssuerLocation(String issuer) {
		Map<String, Object> configuration = getIssuerConfiguration(issuer, OIDC_METADATA_PATH, OAUTH2_METADATA_PATH);
		return withProviderConfiguration(configuration, issuer);
	}

	/**
	 * Validate provided issuer and build {@link JwtDecoder} from
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID Provider
	 * Configuration Response</a> and <a href="https://tools.ietf.org/html/rfc8414#section-3.2">Authorization Server Metadata
	 * Response</a>.
	 *
	 * @param configuration
	 * @param issuer
	 * @return {@link JwtDecoder}
	 */
	private static JwtDecoder withProviderConfiguration(Map<String, Object> configuration, String issuer) {
		String metadataIssuer = "(unavailable)";
		if (configuration.containsKey("issuer")) {
			metadataIssuer = configuration.get("issuer").toString();
		}
		if (!issuer.equals(metadataIssuer)) {
			throw new IllegalStateException("The Issuer \"" + metadataIssuer + "\" provided in the configuration did not "
					+ "match the requested issuer \"" + issuer + "\"");
		}

		OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefaultWithIssuer(issuer);
		NimbusJwtDecoder jwtDecoder = withJwkSetUri(configuration.get("jwks_uri").toString()).build();
		jwtDecoder.setJwtValidator(jwtValidator);

		return jwtDecoder;
	}

	/**
	 * When the length of paths is equal to one (1) then it's a request for OpenId v1 discovery endpoint
	 * hence a request to <strong>{host}/issuer1/.well-known/openid-configuration</strong> is being made.
	 * Otherwise, all three (3) discovery endpoint are queried one after another depending one after another
	 * until one endpoint returns successful response.
	 *
	 * @param issuer
	 * @param paths
	 * @throws IllegalArgumentException if the paths is null or empty or if none of the providers
	 * responded to given issuer and paths requests
	 * @return Map<String, Object> - Configuration Metadata from the given issuer
	 */
	private static Map<String, Object> getIssuerConfiguration(String issuer, String... paths) {
		Assert.notEmpty(paths, "paths cannot be empty or null.");

		URI[] uris = buildIssuerConfigurationUrls(issuer, paths);
		for (URI uri: uris) {
			Map<String, Object> response = makeIssuerRequest(uri);
			if (response != null) {
				return response;
			}
		}
		throw new IllegalArgumentException("Unable to resolve Configuration with the provided Issuer of \"" + issuer + "\"");
	}

	/**
	 * Make a rest API request to the given URI that is either of OpenId, OpenId Connection Discovery 1.0 or OAuth2 and if
	 * successful then return the Response as key-value map. If the request is not successful then the thrown exception is
	 * caught and null is returned indicating no provider available.
	 *
	 * @param uri
	 * @return Map<String, Object> Configuration Metadata of the given provider if not null
	 */
	private static Map<String, Object> makeIssuerRequest(URI uri) {
		RestTemplate rest = new RestTemplate();
		ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {};
		try {
			RequestEntity<Void> request = RequestEntity.get(uri).build();
			return rest.exchange(request, typeReference).getBody();
		} catch(RestClientException ex) {
			return null;
		} catch(RuntimeException ex) {
			return null;
		}
	}

	/**
	 * When invoked with a path then make a
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">
	 * OpenID Provider Configuration Request</a> by querying the OpenId Connection Discovery 1.0 endpoint
	 * and the url would look as follow <strong>{host}/issuer1/.well-known/openid-configuration</strong>
	 *
	 * <p>
	 * When more than one path is provided then query all the three (3) endpoints for metadata configuration
	 * as per <a href="https://tools.ietf.org/html/rfc8414#section-5">Section 5</a> of RF 8414 specification
	 * and the urls would look as follow
	 * </p>
	 *
	 * <ol>
	 * <li>
	 * <strong>{host}/.well-known/openid-configuration/issuer1</strong>  - OpenID as per RFC 8414
	 * </li>
	 * <li>
	 * <strong>{host}/issuer1/.well-known/openid-configuration</strong>  - OpenID Connect 1.0 Discovery Compatibility as per RFC 8414
	 * </li>
	 * <li>
	 * <strong>{host}/.well-known/oauth-authorization-server/issuer1</strong>  - OAuth2 Authorization Server Metadata as per RFC 8414
	 * </li>
	 * </ol>
	 *
	 * @param issuer
	 * @param paths
	 * @throws IllegalArgumentException throws exception if paths length is not 1 or 3, 1 for <strong>fromOidcLocationIssuer</strong>
	 * and 3 for the newly introduced <strong>fromIssuerLocation</strong> to support querying 3 different metadata provider endpoints
	 * @return URI[] URIs for to <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">
	 * OpenID Provider Configuration Response</a> and <a href="https://tools.ietf.org/html/rfc8414#section-3.2">
	 * Authorization Server Metadata Response</a>
	 */
	private static URI[] buildIssuerConfigurationUrls(String issuer, String... paths) {
		Assert.isTrue(paths.length != 1 || paths.length != 3, "paths length can either be 1 or 3");
		URI issuerURI = URI.create(issuer);

		if (paths.length == 1) {
			return new URI[] {
					UriComponentsBuilder.fromUri(issuerURI).replacePath(issuerURI.getPath() + paths[0]).build().toUri()
			};
		} else {
			return new URI[] {
					UriComponentsBuilder.fromUri(issuerURI).replacePath(paths[0] + issuerURI.getPath()).build().toUri(),
					UriComponentsBuilder.fromUri(issuerURI).replacePath(issuerURI.getPath() + paths[0]).build().toUri(),
					UriComponentsBuilder.fromUri(issuerURI).replacePath(paths[1] + issuerURI.getPath()).build().toUri()
			};
		}
	}

	private JwtDecoders() {}
}
