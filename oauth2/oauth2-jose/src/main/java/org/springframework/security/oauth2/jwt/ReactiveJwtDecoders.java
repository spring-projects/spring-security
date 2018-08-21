/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.jwt;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

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
	 * <a href="http://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> by making an
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> and using the values in the
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the {@link ReactiveJwtDecoder}.
	 *
	 * @param oidcIssuerLocation the <a href="http://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link ReactiveJwtDecoder} that was initialized by the OpenID Provider Configuration.
	 */
	public static ReactiveJwtDecoder fromOidcIssuerLocation(String oidcIssuerLocation) {
		String openidConfiguration = getOpenidConfiguration(oidcIssuerLocation);
		OIDCProviderMetadata metadata = parse(openidConfiguration);
		String metadataIssuer = metadata.getIssuer().getValue();
		if (!oidcIssuerLocation.equals(metadataIssuer)) {
			throw new IllegalStateException("The Issuer \"" + metadataIssuer + "\" provided in the OpenID Configuration " +
					"did not match the requested issuer \"" + oidcIssuerLocation + "\"");
		}

		OAuth2TokenValidator<Jwt> jwtValidator =
				JwtValidators.createDefaultWithIssuer(oidcIssuerLocation);

		NimbusReactiveJwtDecoder jwtDecoder =
				new NimbusReactiveJwtDecoder(metadata.getJWKSetURI().toASCIIString());
		jwtDecoder.setJwtValidator(jwtValidator);

		return jwtDecoder;
	}

	private static String getOpenidConfiguration(String issuer) {
		RestTemplate rest = new RestTemplate();
		try {
			return rest.getForObject(issuer + "/.well-known/openid-configuration", String.class);
		} catch(RuntimeException e) {
			throw new IllegalArgumentException("Unable to resolve the OpenID Configuration with the provided Issuer of " +
					"\"" + issuer + "\"", e);
		}
	}

	private static OIDCProviderMetadata parse(String body) {
		try {
			return OIDCProviderMetadata.parse(body);
		}
		catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	private ReactiveJwtDecoders() {}
}
