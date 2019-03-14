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
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import static org.springframework.security.oauth2.jwt.JwtProcessors.withJwkSetUri;

/**
 * Allows creating a {@link JwtDecoder} from an
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Provider Configuration</a>.
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class JwtDecoders {

	/**
	 * Creates a {@link JwtDecoder} using the provided
	 * <a href="http://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> by making an
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> and using the values in the
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the {@link JwtDecoder}.
	 *
	 * @param oidcIssuerLocation the <a href="http://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link JwtDecoder} that was initialized by the OpenID Provider Configuration.
	 */
	public static JwtDecoder fromOidcIssuerLocation(String oidcIssuerLocation) {
		Map<String, Object> openidConfiguration = getOpenidConfiguration(oidcIssuerLocation);
		String metadataIssuer = "(unavailable)";
		if (openidConfiguration.containsKey("issuer")) {
			metadataIssuer = openidConfiguration.get("issuer").toString();
		}
		if (!oidcIssuerLocation.equals(metadataIssuer)) {
			throw new IllegalStateException("The Issuer \"" + metadataIssuer + "\" provided in the OpenID Configuration " +
					"did not match the requested issuer \"" + oidcIssuerLocation + "\"");
		}

		OAuth2TokenValidator<Jwt> jwtValidator =
				JwtValidators.createDefaultWithIssuer(oidcIssuerLocation);

		NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(
				withJwkSetUri(openidConfiguration.get("jwks_uri").toString()).build());
		jwtDecoder.setJwtValidator(jwtValidator);

		return jwtDecoder;
	}

	private static Map<String, Object> getOpenidConfiguration(String issuer) {
		ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {};
		RestTemplate rest = new RestTemplate();
		try {
			URI uri = UriComponentsBuilder.fromUriString(issuer + "/.well-known/openid-configuration")
					.build()
					.toUri();
			RequestEntity<Void> request = RequestEntity.get(uri).build();
			return rest.exchange(request, typeReference).getBody();
		} catch(RuntimeException e) {
			throw new IllegalArgumentException("Unable to resolve the OpenID Configuration with the provided Issuer of " +
					"\"" + issuer + "\"", e);
		}
	}

	private JwtDecoders() {}
}
