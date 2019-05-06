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
import java.util.function.Function;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.core.OAuth2MetadataClientBuilder;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.web.client.RestTemplate;

/**
 * Allows creating a {@link ReactiveJwtDecoder} from an
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Provider Configuration</a>.
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
		Function<URI, Map<String, Object>> client =
				new OAuth2MetadataClientBuilder(client(new RestTemplate()))
						.useOidcDiscovery().build();
		return fromIssuerLocation(client).apply(oidcIssuerLocation);
	}

	private static Function<String, ReactiveJwtDecoder> fromIssuerLocation(
			Function<URI, Map<String, Object>> client) {

		Function<String, URI> toUri = URI::create;
		return toUri.andThen(client).andThen(ReactiveJwtDecoders::fromProviderConfiguration);
	}

	private static ReactiveJwtDecoder fromProviderConfiguration(Map<String, Object> metadata) {
		OAuth2TokenValidator<Jwt> jwtValidator =
				JwtValidators.createDefaultWithIssuer(metadata.get("issuer").toString());

		NimbusReactiveJwtDecoder jwtDecoder =
				new NimbusReactiveJwtDecoder(metadata.get("jwks_uri").toString());
		jwtDecoder.setJwtValidator(jwtValidator);

		return jwtDecoder;
	}

	private static Function<URI, Map<String, Object>> client(RestTemplate rest) {
		ParameterizedTypeReference<Map<String, Object>> typeReference =
				new ParameterizedTypeReference<Map<String, Object>>() {};
		return uri -> {
			RequestEntity<Void> request = RequestEntity.get(uri).build();
			return rest.exchange(request, typeReference).getBody();
		};
	}

	private ReactiveJwtDecoders() {}
}
