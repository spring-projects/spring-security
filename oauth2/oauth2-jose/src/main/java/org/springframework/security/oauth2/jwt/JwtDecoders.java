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
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Allows creating a {@link JwtDecoder} from an
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Provider Configuration</a>.
 *
 * @author Josh Cummings
 * @author Rafiullah Hamedy
 * @since 5.1
 */
public final class JwtDecoders {

	private static final String WELL_KNOWN_PATH = "/.well-known/";
	private static final String OIDC_METADATA_PATH = "openid-configuration";
	private static final String OAUTH2_METADATA_PATH = "oauth-authorization-server";

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
		Map<String, Object> configuration = getOpenIdConfiguration(oidcIssuerLocation);
		return withProviderConfiguration(configuration, oidcIssuerLocation);
	}

	/**
	 * Creates a {@link JwtDecoder} using the provided issuer by making an
	 * <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server Metadata Request</a> and using the
	 * values in the  <a href="https://tools.ietf.org/html/rfc8414#section-3.2">Authorization Server Metadata Response</a>
	 * to initialize the {@link JwtDecoder}.
	 *
	 * @param oauth2IssuerLocation
	 * @return a {@link JwtDecoder} that was initialized by the Authorization Server Metadata Provider Configuration.
	 */
	public static JwtDecoder fromOAuth2IssuerLocation(String oauth2IssuerLocation) {
		Map<String, Object> configuration = getOAuth2Configuration(oauth2IssuerLocation);
		return withProviderConfiguration(configuration, oauth2IssuerLocation);
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
	 *
	 * Make an <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> as per RFC 8414 specification <a href="https://tools.ietf.org/html/rfc8414#section-5">
	 * Compatibility Notes</a> and return the retrieved
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID Provider
	 * Configuration Response</a>.
	 *
	 * @param issuer
	 * @return <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID Provider
	 * Configuration Response</a>
	 */
	private static Map<String, Object> getOpenIdConfiguration(String issuer) {
		final String wellKnownPath = WELL_KNOWN_PATH + OIDC_METADATA_PATH;
		final String invalidIssuerMessage = "Unable to resolve the OpenID Configuration with the provided Issuer of \"" + issuer + "\"";

		ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {};
		RestTemplate rest = new RestTemplate();
		URI uri = URI.create(issuer);
		try {
			URI url = UriComponentsBuilder.fromUri(uri).replacePath(wellKnownPath + uri.getPath()).build().toUri();
			RequestEntity<Void> request = RequestEntity.get(url).build();
			return rest.exchange(request, typeReference).getBody();
		} catch(HttpClientErrorException e) {
			if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
				URI url = UriComponentsBuilder.fromUri(uri).replacePath(uri.getPath() + wellKnownPath).build().toUri();
				RequestEntity<Void> request = RequestEntity.get(url).build();
				return rest.exchange(request, typeReference).getBody();
			} else {
				throw new IllegalArgumentException(invalidIssuerMessage, e);
			}
		} catch(RuntimeException e) {
			throw new IllegalArgumentException(invalidIssuerMessage, e);
		}
	}

	/**
	 *
	 * Make an <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server Metadata Request</a> and return
	 * the retrieved
	 * <a href="https://tools.ietf.org/html/rfc8414#section-3.2">Authorization Server Metadata Response</a>.
	 *
	 * @param issuer
	 * @return <a href="https://tools.ietf.org/html/rfc8414#section-3.2">Authorization Server Metadata Response</a>
	 */
	private static Map<String, Object> getOAuth2Configuration(String issuer) {
		final String wellKnownPath = WELL_KNOWN_PATH + OAUTH2_METADATA_PATH;

		ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {};
		RestTemplate rest = new RestTemplate();
		URI uri = URI.create(issuer);
		try {
			/**
			 * Results in /.well-known/oauth-authorization-server/issuer1 where issuer is https://example.com/issuer1
			 */
			URI url = UriComponentsBuilder.fromUri(uri).replacePath(wellKnownPath + uri.getPath()).build().toUri();
			RequestEntity<Void> request = RequestEntity.get(url).build();
			return rest.exchange(request, typeReference).getBody();
		} catch(RuntimeException e) {
			throw new IllegalArgumentException("Unable to resolve the Authorization Server Metadata with the provided "
					+ "Issuer of \"" + issuer + "\"", e);
		}
	}

	private JwtDecoders() {}
}
