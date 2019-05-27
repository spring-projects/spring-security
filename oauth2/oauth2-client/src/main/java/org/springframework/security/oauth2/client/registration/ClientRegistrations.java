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

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

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
	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";
	private static final String OAUTH2_METADATA_PATH = "/.well-known/oauth-authorization-server";

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
		String configuration = getIssuerConfiguration(issuer, OIDC_METADATA_PATH);
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
		String configuration = getIssuerConfiguration(issuer, OIDC_METADATA_PATH, OAUTH2_METADATA_PATH);
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

	/**
	 * When the length of paths is equal to one (1) then it's a request for OpenId v1 discovery endpoint
	 * hence a request to "/issuer1/.well-known/openid-configuration" is being made. Otherwise, all
	 * three (3) discovery endpoint are queried one after another depending on result of previous query
	 * as shown below in the following order
	 *
	 * 1) Request "/.well-known/openid-configuration/issuer1"
	 *
	 * 2) If (1) is not resolved then request "/issuer1/.well-known/openid-configuration"
	 *
	 * 3) If (2) is not resolved then request "/.well-known/oauth-authorization-server/issuer1"
	 *
	 * If none of the above is resolved then thrown an error indicating that issuer could not be
	 * resolved.
	 *
	 * @param issuer
	 * @param paths
	 * @return String Configuration Metadata
	 */
	private static String getIssuerConfiguration(String issuer, String... paths) {
		Assert.notEmpty(paths, "paths cannot be empty or null.");

		String[] urls = buildIssuerConfigurationURLs(issuer, paths);
		for(String url: urls) {
			String response = makeIssuerRequest(url);
			if(response != null) {
				return response;
			}
		}
		throw new IllegalArgumentException("Unable to resolve Configuration with the provided Issuer of \"" + issuer + "\"");
	}

	private static String makeIssuerRequest(String uri) {
		RestTemplate rest = new RestTemplate();
		try {
			return rest.getForObject(uri, String.class);
		} catch(RuntimeException ex) {
			return null;
		}
	}

	private static String[] buildIssuerConfigurationURLs(String issuer, String... paths) {
		Assert.isTrue(paths.length == 1 || paths.length == 2, "");
		URI issuerURI = URI.create(issuer);

		if(paths.length == 1) {
			return new String[] {
					/**
					 * Results in /issuer1/.well-known/openid-configuration for backward compatibility
					 */
					UriComponentsBuilder.fromUri(issuerURI).replacePath(issuerURI.getPath() + paths[0]).toUriString()
			};
		} else {
			 return new String[] {
					 /**
					  * Returns an array of URLs as follow when issuer1 is provided
					  *
					  * [0] => /.well-known/openid-configuration/issuer1 that follows
					  *
					  * [1] => /issuer1/.well-known/openid-configuration for backward compatibility as explained in
					  * the <a href="https://tools.ietf.org/html/rfc8414#section-5">Section 5</a> of RF 8414
					  *
					  * [2] => /.well-known/oauth-authorization-server/issuer1
					  *
					  */
					 UriComponentsBuilder.fromUri(issuerURI).replacePath(paths[0] + issuerURI.getPath()).toUriString(),
					 UriComponentsBuilder.fromUri(issuerURI).replacePath(issuerURI.getPath() + paths[0]).toUriString(),
					 UriComponentsBuilder.fromUri(issuerURI).replacePath(paths[1] + issuerURI.getPath()).toUriString()
			 };
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
