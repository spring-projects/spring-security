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

package org.springframework.security.oauth2.client.registration;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import net.minidev.json.JSONObject;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2MetadataClientBuilder;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.web.client.RestTemplate;

/**
 * Allows creating a {@link ClientRegistration.Builder} from an
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Provider Configuration</a>.
 *
 * @author Rob Winch
 * @author Josh Cummings
 * @since 5.1
 */
public final class ClientRegistrations {

	/**
	 * Creates a {@link ClientRegistration.Builder}  using the provided
	 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> by making an
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> and using the values in the
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the {@link ClientRegistration.Builder}.
	 *
	 * <p>
	 * For example, if the issuer provided is "https://example.com", then an "OpenID Provider Configuration Request" will
	 * be made to "https://example.com/.well-known/openid-configuration". The result is expected to be an "OpenID
	 * Provider Configuration Response".
	 * </p>
	 *
	 * <p>
	 * Example usage:
	 * </p>
	 * <pre>
	 * ClientRegistration registration = ClientRegistrations.fromOidcIssuerLocation("https://example.com")
	 *     .clientId("client-id")
	 *     .clientSecret("client-secret")
	 *     .build();
	 * </pre>
	 * @param issuer the <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link ClientRegistration.Builder} that was initialized by the OpenID Provider Configuration.
	 */
	public static ClientRegistration.Builder fromOidcIssuerLocation(String issuer) {
		Function<URI, Map<String, Object>> client =
				new OAuth2MetadataClientBuilder(client(new RestTemplate()))
						.useOidcDiscovery().build();
		return fromIssuerLocation(client, issuer).apply(issuer);
	}

	public static ClientRegistration.Builder fromIssuerLocation(String issuer,
			Consumer<OAuth2MetadataClientBuilder> metadataClientBuilderConsumer) {
		OAuth2MetadataClientBuilder metadataClientBuilder =
				new OAuth2MetadataClientBuilder(client(new RestTemplate()));
		metadataClientBuilderConsumer.accept(metadataClientBuilder);
		return fromIssuerLocation(metadataClientBuilder.build(), issuer).apply(issuer);
	}

	private static Function<URI, Map<String, Object>> client(RestTemplate rest) {
		ParameterizedTypeReference<Map<String, Object>> typeReference =
				new ParameterizedTypeReference<Map<String, Object>>() {};
		return uri -> {
			RequestEntity<Void> request = RequestEntity.get(uri).build();
			return rest.exchange(request, typeReference).getBody();
		};
	}

	private static Function<String, ClientRegistration.Builder> fromIssuerLocation(
			Function<URI, Map<String, Object>> client, String issuer) {

		Function<String, URI> toUri = URI::create;
		return toUri.andThen(client)
				.andThen(ClientRegistrations::parseAuthorizationServer)
				.andThen(metadata -> fromProviderConfiguration(metadata, issuer));
	}

	private static AuthorizationServerMetadata parseAuthorizationServer(Map<String, Object> body) {
		try {
			return AuthorizationServerMetadata.parse(new JSONObject(body));
		} catch (ParseException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static ClientRegistration.Builder fromProviderConfiguration(AuthorizationServerMetadata metadata, String issuer) {
		String name = URI.create(issuer).getHost();
		ClientAuthenticationMethod method = getClientAuthenticationMethod(issuer, metadata.getTokenEndpointAuthMethods());
		List<GrantType> grantTypes = metadata.getGrantTypes();
		// If null, the default includes authorization_code
		if (grantTypes != null && !grantTypes.contains(GrantType.AUTHORIZATION_CODE)) {
			throw new IllegalArgumentException("Only AuthorizationGrantType.AUTHORIZATION_CODE is supported. The issuer \"" + issuer + "\" returned a configuration of " + grantTypes);
		}
		List<String> scopes = getScopes(metadata);
		Map<String, Object> configurationMetadata = new LinkedHashMap<>(metadata.toJSONObject());

		ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(name)
				.userNameAttributeName(IdTokenClaimNames.SUB)
				.scope(scopes)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(method)
				.redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}")
				.authorizationUri(metadata.getAuthorizationEndpointURI().toASCIIString())
				.jwkSetUri(metadata.getJWKSetURI().toASCIIString())
				.providerConfigurationMetadata(configurationMetadata)
				.tokenUri(metadata.getTokenEndpointURI().toASCIIString())
				.clientName(issuer);

		return getUserInfoEndpoint(configurationMetadata)
				.map(builder::userInfoUri)
				.orElse(builder);

	}


	private static ClientAuthenticationMethod getClientAuthenticationMethod(String issuer, List<com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod> metadataAuthMethods) {
		if (metadataAuthMethods == null || metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
			// If null, the default includes client_secret_basic
			return ClientAuthenticationMethod.BASIC;
		}
		if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
			return ClientAuthenticationMethod.POST;
		}
		if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE)) {
			return ClientAuthenticationMethod.NONE;
		}
		throw new IllegalArgumentException("Only ClientAuthenticationMethod.BASIC, ClientAuthenticationMethod.POST and ClientAuthenticationMethod.NONE are supported. The issuer \"" + issuer + "\" returned a configuration of " + metadataAuthMethods);
	}

	private static List<String> getScopes(AuthorizationServerMetadata metadata) {
		Scope scope = metadata.getScopes();
		if (scope == null) {
			// If null, default to "openid" which must be supported
			return Collections.singletonList(OidcScopes.OPENID);
		} else {
			return scope.toStringList();
		}
	}

	private static Optional<String> getUserInfoEndpoint(Map<String, Object> metadata) {
		return Optional.ofNullable(metadata.get("userinfo_endpoint"))
				.map(Objects::toString)
				.map(URI::create)
				.map(URI::toASCIIString);
	}

	private ClientRegistrations() {}

}
