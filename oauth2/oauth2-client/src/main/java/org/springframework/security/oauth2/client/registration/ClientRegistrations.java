/*
 * Copyright 2002-2021 the original author or authors.
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
import java.util.function.Supplier;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import net.minidev.json.JSONObject;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.util.Assert;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Allows creating a {@link ClientRegistration.Builder} from an <a href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID
 * Provider Configuration</a> or
 * <a href="https://tools.ietf.org/html/rfc8414#section-3">Authorization Server
 * Metadata</a> based on provided issuer.
 *
 * @author Rob Winch
 * @author Josh Cummings
 * @author Rafiullah Hamedy
 * @since 5.1
 */
public final class ClientRegistrations {

	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";

	private static final String OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";

	private static final RestTemplate rest = new RestTemplate();

	static {
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setConnectTimeout(30_000);
		requestFactory.setReadTimeout(30_000);
		rest.setRequestFactory(requestFactory);
	}

	private static final ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	private ClientRegistrations() {
	}

	/**
	 * Creates a {@link ClientRegistration.Builder} using the provided <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * by making an <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID
	 * Provider Configuration Request</a> and using the values in the <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the
	 * {@link ClientRegistration.Builder}.
	 *
	 * <p>
	 * For example, if the issuer provided is "https://example.com", then an "OpenID
	 * Provider Configuration Request" will be made to
	 * "https://example.com/.well-known/openid-configuration". The result is expected to
	 * be an "OpenID Provider Configuration Response".
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
	 * @param issuer the <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link ClientRegistration.Builder} that was initialized by the OpenID
	 * Provider Configuration.
	 */
	public static ClientRegistration.Builder fromOidcIssuerLocation(String issuer) {
		Assert.hasText(issuer, "issuer cannot be empty");
		return getBuilder(issuer, oidc(URI.create(issuer)));
	}

	/**
	 * Creates a {@link ClientRegistration.Builder} using the provided <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * by querying three different discovery endpoints serially, using the values in the
	 * first successful response to initialize. If an endpoint returns anything other than
	 * a 200 or a 4xx, the method will exit without attempting subsequent endpoints.
	 *
	 * The three endpoints are computed as follows, given that the {@code issuer} is
	 * composed of a {@code host} and a {@code path}:
	 *
	 * <ol>
	 * <li>{@code host/.well-known/openid-configuration/path}, as defined in
	 * <a href="https://tools.ietf.org/html/rfc8414#section-5">RFC 8414's Compatibility
	 * Notes</a>.</li>
	 * <li>{@code issuer/.well-known/openid-configuration}, as defined in <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">
	 * OpenID Provider Configuration</a>.</li>
	 * <li>{@code host/.well-known/oauth-authorization-server/path}, as defined in
	 * <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server
	 * Metadata Request</a>.</li>
	 * </ol>
	 *
	 * Note that the second endpoint is the equivalent of calling
	 * {@link ClientRegistrations#fromOidcIssuerLocation(String)}.
	 *
	 * <p>
	 * Example usage:
	 * </p>
	 * <pre>
	 * ClientRegistration registration = ClientRegistrations.fromIssuerLocation("https://example.com")
	 *     .clientId("client-id")
	 *     .clientSecret("client-secret")
	 *     .build();
	 * </pre>
	 * @param issuer
	 * @return a {@link ClientRegistration.Builder} that was initialized by one of the
	 * described endpoints
	 */
	public static ClientRegistration.Builder fromIssuerLocation(String issuer) {
		Assert.hasText(issuer, "issuer cannot be empty");
		URI uri = URI.create(issuer);
		return getBuilder(issuer, oidc(uri), oidcRfc8414(uri), oauth(uri));
	}

	private static Supplier<ClientRegistration.Builder> oidc(URI issuer) {
		// @formatter:off
		URI uri = UriComponentsBuilder.fromUri(issuer)
				.replacePath(issuer.getPath() + OIDC_METADATA_PATH)
				.build(Collections.emptyMap());
		// @formatter:on
		return () -> {
			RequestEntity<Void> request = RequestEntity.get(uri).build();
			Map<String, Object> configuration = rest.exchange(request, typeReference).getBody();
			OIDCProviderMetadata metadata = parse(configuration, OIDCProviderMetadata::parse);
			ClientRegistration.Builder builder = withProviderConfiguration(metadata, issuer.toASCIIString())
					.jwkSetUri(metadata.getJWKSetURI().toASCIIString());
			if (metadata.getUserInfoEndpointURI() != null) {
				builder.userInfoUri(metadata.getUserInfoEndpointURI().toASCIIString());
			}
			return builder;
		};
	}

	private static Supplier<ClientRegistration.Builder> oidcRfc8414(URI issuer) {
		// @formatter:off
		URI uri = UriComponentsBuilder.fromUri(issuer)
				.replacePath(OIDC_METADATA_PATH + issuer.getPath())
				.build(Collections.emptyMap());
		// @formatter:on
		return getRfc8414Builder(issuer, uri);
	}

	private static Supplier<ClientRegistration.Builder> oauth(URI issuer) {
		// @formatter:off
		URI uri = UriComponentsBuilder.fromUri(issuer)
				.replacePath(OAUTH_METADATA_PATH + issuer.getPath())
				.build(Collections.emptyMap());
		// @formatter:on
		return getRfc8414Builder(issuer, uri);
	}

	private static Supplier<ClientRegistration.Builder> getRfc8414Builder(URI issuer, URI uri) {
		return () -> {
			RequestEntity<Void> request = RequestEntity.get(uri).build();
			Map<String, Object> configuration = rest.exchange(request, typeReference).getBody();
			AuthorizationServerMetadata metadata = parse(configuration, AuthorizationServerMetadata::parse);
			ClientRegistration.Builder builder = withProviderConfiguration(metadata, issuer.toASCIIString());
			URI jwkSetUri = metadata.getJWKSetURI();
			if (jwkSetUri != null) {
				builder.jwkSetUri(jwkSetUri.toASCIIString());
			}
			String userinfoEndpoint = (String) configuration.get("userinfo_endpoint");
			if (userinfoEndpoint != null) {
				builder.userInfoUri(userinfoEndpoint);
			}
			return builder;
		};
	}

	@SafeVarargs
	private static ClientRegistration.Builder getBuilder(String issuer,
			Supplier<ClientRegistration.Builder>... suppliers) {
		String errorMessage = "Unable to resolve Configuration with the provided Issuer of \"" + issuer + "\"";
		for (Supplier<ClientRegistration.Builder> supplier : suppliers) {
			try {
				return supplier.get();
			}
			catch (HttpClientErrorException ex) {
				if (!ex.getStatusCode().is4xxClientError()) {
					throw ex;
				}
				// else try another endpoint
			}
			catch (IllegalArgumentException | IllegalStateException ex) {
				throw ex;
			}
			catch (RuntimeException ex) {
				throw new IllegalArgumentException(errorMessage, ex);
			}
		}
		throw new IllegalArgumentException(errorMessage);
	}

	private static <T> T parse(Map<String, Object> body, ThrowingFunction<JSONObject, T, ParseException> parser) {
		try {
			return parser.apply(new JSONObject(body));
		}
		catch (ParseException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static ClientRegistration.Builder withProviderConfiguration(AuthorizationServerMetadata metadata,
			String issuer) {
		String metadataIssuer = metadata.getIssuer().getValue();
		Assert.state(issuer.equals(metadataIssuer),
				() -> "The Issuer \"" + metadataIssuer + "\" provided in the configuration metadata did "
						+ "not match the requested issuer \"" + issuer + "\"");
		String name = URI.create(issuer).getHost();
		ClientAuthenticationMethod method = getClientAuthenticationMethod(metadata.getTokenEndpointAuthMethods());
		Map<String, Object> configurationMetadata = new LinkedHashMap<>(metadata.toJSONObject());
		// @formatter:off
		return ClientRegistration.withRegistrationId(name)
				.userNameAttributeName(IdTokenClaimNames.SUB)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(method)
				.redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
				.authorizationUri((metadata.getAuthorizationEndpointURI() != null) ? metadata.getAuthorizationEndpointURI().toASCIIString() : null)
				.providerConfigurationMetadata(configurationMetadata)
				.tokenUri(metadata.getTokenEndpointURI().toASCIIString())
				.issuerUri(issuer)
				.clientName(issuer);
		// @formatter:on
	}

	private static ClientAuthenticationMethod getClientAuthenticationMethod(
			List<com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod> metadataAuthMethods) {
		if (metadataAuthMethods == null || metadataAuthMethods
				.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
			// If null, the default includes client_secret_basic
			return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		}
		if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_POST;
		}
		if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE)) {
			return ClientAuthenticationMethod.NONE;
		}
		return null;
	}

	private interface ThrowingFunction<S, T, E extends Throwable> {

		T apply(S src) throws E;

	}

}
