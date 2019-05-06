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

import java.net.URI;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.core.OAuth2MetadataClientBuilder;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.web.client.RestTemplate;

import static org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withJwkSetUri;

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
		Function<URI, Map<String, Object>> client =
				new OAuth2MetadataClientBuilder(client(new RestTemplate()))
						.useOidcDiscovery().build();
		return fromIssuerLocation(client).apply(oidcIssuerLocation);
	}

	public static JwtDecoder fromIssuerLocation(String issuer,
			Consumer<OAuth2MetadataClientBuilder> metadataClientBuilderConsumer) {

		OAuth2MetadataClientBuilder metadataClientBuilder =
				new OAuth2MetadataClientBuilder(client(new RestTemplate()));
		metadataClientBuilderConsumer.accept(metadataClientBuilder);
		return fromIssuerLocation(metadataClientBuilder.build()).apply(issuer);
	}

	private static Function<String, JwtDecoder> fromIssuerLocation(
			Function<URI, Map<String, Object>> client) {

		Function<String, URI> toUri = URI::create;
		return toUri.andThen(client).andThen(JwtDecoders::fromProviderConfiguration);
	}

	private static JwtDecoder fromProviderConfiguration(Map<String, Object> metadata) {
		OAuth2TokenValidator<Jwt> jwtValidator =
				JwtValidators.createDefaultWithIssuer(metadata.get("issuer").toString());

		NimbusJwtDecoder jwtDecoder = withJwkSetUri(metadata.get("jwks_uri").toString()).build();
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

	private JwtDecoders() {}
}
