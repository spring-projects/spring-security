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

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Allows creating a {@link ClientRegistration.Builder} from an
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Provider Configuration</a>
 * and
 * <a href="https://tools.ietf.org/html/rfc8414#section-3">Obtaining Authorization Server Metadata</a>.
 *
 * @author Rob Winch
 * @author Josh Cummings
 * @author Rafiullah Hamedy
 * @since 5.1
 */
public final class ClientRegistrations {

	private static final String WELL_KNOWN_PATH = "/.well-known/";
	private static final String OIDC_METADATA_PATH = "openid-configuration";
	private static final String OAUTH2_METADATA_PATH = "oauth-authorization-server";

	/**
	 * Creates a {@link ClientRegistration.Builder}  using the provided
	 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> by making an
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> and using the values in the
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the {@link ClientRegistration.Builder}.
	 *
	 * When deployed in legacy environments using OpenID Connect Discovery 1.0 and if the provided issuer has
	 * a path i.e. /issuer1 then as per <a href="https://tools.ietf.org/html/rfc8414#section-5">Compatibility Notes</a>
	 * first make an <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> using path /.well-known/openid-configuration/issuer1 and only if the retrieval
	 * fail then a subsequent request to path /issuer1/.well-known/openid-configuration should be made.
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
		String configuration = getOpenIdConfiguration(issuer);
		OIDCProviderMetadata metadata = parse(configuration, OIDCProviderMetadata::parse);
		return withProviderConfiguration(metadata, issuer)
				.userInfoUri(metadata.getUserInfoEndpointURI().toASCIIString());
	}

	/**
	 * Creates a {@link ClientRegistration.Builder} using the provided issuer by making an
	 * <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server Metadata Request</a> and using the
	 * values in the <a href="https://tools.ietf.org/html/rfc8414#section-3.2">Authorization Server Metadata Response</a>
	 * to initialize the {@link ClientRegistration.Builder}.
	 *
	 * <p>
	 * For example, if the issuer provided is "https://example.com", then an "Authorization Server Metadata Request" will
	 * be made to "https://example.com/.well-known/oauth-authorization-server". The result is expected to be an "Authorization
	 * Server Metadata Response".
	 * </p>
	 *
	 * <p>
	 * Example usage:
	 * </p>
	 * <pre>
	 * ClientRegistration registration = ClientRegistrations.fromOAuth2IssuerLocation("https://example.com")
	 *     .clientId("client-id")
	 *     .clientSecret("client-secret")
	 *     .build();
	 * </pre>
	 * @param issuer
	 * @return a {@link ClientRegistration.Builder} that was initialized by the Authorization Sever Metadata Provider
	 */
	public static ClientRegistration.Builder fromOAuth2IssuerLocation(String issuer) {
		String configuration = getOAuth2Configuration(issuer);
		AuthorizationServerMetadata metadata = parse(configuration, AuthorizationServerMetadata::parse);
		return withProviderConfiguration(metadata, issuer);
	}

	private static ClientRegistration.Builder withProviderConfiguration(AuthorizationServerMetadata metadata, String issuer) {
		String metadataIssuer = metadata.getIssuer().getValue();
		if (!issuer.equals(metadataIssuer)) {
			throw new IllegalStateException("The Issuer \"" + metadataIssuer + "\" provided in the configuration metadata did "
					+ "not match the requested issuer \"" + issuer + "\"");
		}

		String name = URI.create(issuer).getHost();
		ClientAuthenticationMethod method = getClientAuthenticationMethod(issuer, metadata.getTokenEndpointAuthMethods());
		List<GrantType> grantTypes = metadata.getGrantTypes();
		// If null, the default includes authorization_code
		if (grantTypes != null && !grantTypes.contains(GrantType.AUTHORIZATION_CODE)) {
			throw new IllegalArgumentException("Only AuthorizationGrantType.AUTHORIZATION_CODE is supported. The issuer \"" + issuer +
					"\" returned a configuration of " + grantTypes);
		}
		List<String> scopes = getScopes(metadata);
		Map<String, Object> configurationMetadata = new LinkedHashMap<>(metadata.toJSONObject());

		return ClientRegistration.withRegistrationId(name)
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
	}

	private static String getOpenIdConfiguration(String issuer) {
		final String wellKnownPath = WELL_KNOWN_PATH + OIDC_METADATA_PATH;
		final String invalidIssuerMessage = "Unable to resolve the OpenID Configuration with the provided Issuer of \"" + issuer + "\"";

		RestTemplate rest = new RestTemplate();

		URI uri = URI.create(issuer);
		try {
			/**
			 * Results in /.well-known/openid-configuration/issuer1 assuming issuer is https://example.com/issuer1
			 */
			String url = UriComponentsBuilder.fromUri(uri).replacePath(wellKnownPath + uri.getPath()).toUriString();
			return rest.getForObject(url, String.class);
		} catch(HttpClientErrorException e) {
			if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
				 /**
				  * As per the <a href="https://tools.ietf.org/html/rfc8414#section-5">Section 5</a> when the first attempt for
				  * https://example.com/.well-known/openid-configuration/issuer1 failed then for backward compatibility
				  * check https://example.com/issuer1/.well-known/openid-configuration for Open ID only.
				  *
				  * Results in /issuer1/.well-known/openid-configuration where issuer is https://example.com/issuer1
				  */
				String url = UriComponentsBuilder.fromUri(uri).replacePath(uri.getPath() + wellKnownPath).toUriString();
				return rest.getForObject(url, String.class);
			} else {
				throw new IllegalArgumentException(invalidIssuerMessage, e);
			}
		} catch(RuntimeException e) {
			throw new IllegalArgumentException(invalidIssuerMessage, e);
		}
	}

	private static String getOAuth2Configuration(String issuer) {
		final String wellKnownPath = WELL_KNOWN_PATH + OAUTH2_METADATA_PATH;

		RestTemplate rest = new RestTemplate();

		URI uri = URI.create(issuer);
		try {
			/**
			 * Results in /.well-known/oauth-authorization-server/issuer1 where issuer is https://example.com/issuer1
			 */
			String url = UriComponentsBuilder.fromUri(uri).replacePath(wellKnownPath + uri.getPath()).toUriString();
			return rest.getForObject(url, String.class);
		} catch(RuntimeException e) {
			throw new IllegalArgumentException("Unable to resolve the Authorization Server Metadata with the provided "
					+ "Issuer of \"" + issuer + "\"", e);
		}
	}

	private static ClientAuthenticationMethod getClientAuthenticationMethod(String issuer,
			List<com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod> metadataAuthMethods) {
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
		throw new IllegalArgumentException("Only ClientAuthenticationMethod.BASIC, ClientAuthenticationMethod.POST and "
				+ "ClientAuthenticationMethod.NONE are supported. The issuer \"" + issuer + "\" returned a configuration of " + metadataAuthMethods);
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

	private static <T> T parse(String body, ThrowingFunction<String, T, ParseException> parser) {
		try {
			return parser.apply(body);
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	private interface ThrowingFunction<S, T, E extends Throwable> {
		T apply(S src) throws E;
	}

	private ClientRegistrations() {}

}
