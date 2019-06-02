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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Allows creating a {@link ClientRegistration.Builder} from an
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Provider Configuration</a>
 * or <a href="https://tools.ietf.org/html/rfc8414#section-3">Authorization Server Metadata</a> based on
 * provided issuer.
 *
 * @author Rob Winch
 * @author Josh Cummings
 * @author Rafiullah Hamedy
 * @since 5.1
 */
public final class ClientRegistrations {
	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";
	private static final String OAUTH2_METADATA_PATH = "/.well-known/oauth-authorization-server";

	enum ProviderType {
		OIDCV1, OIDC, OAUTH2;
	}

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
		Map<ProviderType, String> configuration = getIssuerConfiguration(issuer, OIDC_METADATA_PATH);
		OIDCProviderMetadata metadata = parse(configuration.get(ProviderType.OIDCV1), OIDCProviderMetadata::parse);
		return withProviderConfiguration(metadata, issuer)
				.userInfoUri(metadata.getUserInfoEndpointURI().toASCIIString());
	}

	/**
	 * Unlike <strong>fromOidcIssuerLocation</strong> the <strong>fromIssuerLocation</strong> queries three different endpoints and uses the
	 * returned response from whichever that returns successfully. When <strong>fromIssuerLocation</strong> is invoked with an issuer
	 * the following sequence of actions take place
	 *
	 * <ol>
	 * 	<li>
	 *     The first request is made against <i>{host}/.well-known/openid-configuration/issuer1</i> where issuer is equal to
	 *     <strong>issuer1</strong>. See <a href="https://tools.ietf.org/html/rfc8414#section-5">Compatibility Notes</a> of RFC 8414
	 *     specification for more details.
	 *  </li>
	 *  <li>
	 *  	If the first attempt request returned non-Success (i.e. 200 status code) response then based on <strong>Compatibility Notes</strong> of
	 *  <strong>RFC 8414</strong> a fallback <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">
	 *  OpenID Provider Configuration Request</a> is made to <i>{host}/issuer1/.well-known/openid-configuration</i>
	 *  </li>
	 *  <li>
	 *  	If the second attempted request returns a non-Success (i.e. 200 status code) response then based a final
	 *  <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server Metadata Request</a> is being made to
	 *  <i>{host}/.well-known/oauth-authorization-server/issuer1</i>.
	 *  </li>
	 * </ol>
	 *
	 *
	 * As explained above, <strong>fromIssuerLocation</strong> would behave the exact same way as <strong>fromOidcIssuerLocation</strong> and that is
	 * because <strong>fromIssuerLocation</strong> does the exact same processing as <strong>fromOidcIssuerLocation</strong> behind the scene. Use of
	 * <strong>fromIssuerLocation</strong> is encouraged due to the fact that it is well-aligned with RFC 8414 specification and more specifically
	 * it queries latest OIDC metadata endpoint with a fallback to legacy OIDC v1 discovery endpoint.
	 *
	 * The <strong>fromIssuerLocation</strong> is based on <a href="https://tools.ietf.org/html/rfc8414">RFC 8414</a> specification.
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
	 *
	 * @param issuer
	 * @return a {@link ClientRegistration.Builder} that was initialized by the Authorization Sever Metadata Provider
	 */
	public static ClientRegistration.Builder fromIssuerLocation(String issuer) {
		Map<ProviderType, String> configuration = getIssuerConfiguration(issuer, OIDC_METADATA_PATH, OAUTH2_METADATA_PATH);

		if (configuration.containsKey(ProviderType.OAUTH2)) {
			AuthorizationServerMetadata metadata = parse(configuration.get(ProviderType.OAUTH2), AuthorizationServerMetadata::parse);
			ClientRegistration.Builder builder = withProviderConfiguration(metadata, issuer);
			return builder;
		} else {
			String response = configuration.getOrDefault(ProviderType.OIDC, configuration.get(ProviderType.OIDCV1));
			OIDCProviderMetadata metadata = parse(response, OIDCProviderMetadata::parse);
			ClientRegistration.Builder builder = withProviderConfiguration(metadata, issuer)
					.userInfoUri(metadata.getUserInfoEndpointURI().toASCIIString());
			return builder;
		}
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
	 * hence the request is made to <strong>{host}/issuer1/.well-known/openid-configuration</strong>.
	 * Otherwise, all three (3) metadata endpoints are queried one after another.
	 *
	 * @param issuer
	 * @param paths
	 * @throws IllegalArgumentException if the paths is null or empty or if none of the providers
	 * responded to given issuer and paths requests
	 * @return Map<String, Object> - Configuration Metadata from the given issuer
	 */
	private static Map<ProviderType, String> getIssuerConfiguration(String issuer, String... paths) {
		Assert.notEmpty(paths, "paths cannot be empty or null.");

		Map<ProviderType, String> providersUrl = buildIssuerConfigurationUrls(issuer, paths);
		Map<ProviderType, String> providerResponse = new HashMap<>();

		if (providersUrl.containsKey(ProviderType.OIDC)) {
			providerResponse = mapResponse(providersUrl, ProviderType.OIDC);
		}

		// Fallback to OpenId v1 Discovery Endpoint based on RFC 8414 Compatibility Notes
		if (providerResponse.isEmpty() && providersUrl.containsKey(ProviderType.OIDCV1)) {
			providerResponse = mapResponse(providersUrl, ProviderType.OIDCV1);
		}

		if (providerResponse.isEmpty() && providersUrl.containsKey(ProviderType.OAUTH2)) {
			providerResponse = mapResponse(providersUrl, ProviderType.OAUTH2);
		}

		if (providerResponse.isEmpty()) {
			throw new IllegalArgumentException("Unable to resolve Configuration with the provided Issuer of \"" + issuer + "\"");
		}
		return providerResponse;
	}

	private static Map<ProviderType, String> mapResponse(Map<ProviderType, String> providersUrl, ProviderType providerType) {
		Map<ProviderType, String> providerResponse = new HashMap<>();
		String response = makeIssuerRequest(providersUrl.get(providerType));
		if (response != null) {
			providerResponse.put(providerType, response);
		}
		return providerResponse;
	}

	private static String makeIssuerRequest(String uri) {
		RestTemplate rest = new RestTemplate();
		try {
			return rest.getForObject(uri, String.class);
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
	 * and the URLs would look as follow
	 * </p>
	 *
	 * <ol>
	 * <li>
	 * <strong>{host}/.well-known/openid-configuration/issuer1</strong>  - OpenID as per RFC 8414
	 * </li>
	 * <li>
	 * <strong>{host}/issuer1/.well-known/openid-configuration</strong> -  OpenID Connect 1.0 Discovery Compatibility as per RFC 8414
	 * </li>
	 * <li>
	 * <strong>/.well-known/oauth-authorization-server/issuer1</strong> - OAuth2 Authorization Server Metadata as per RFC 8414
	 * </li>
	 * </ol>
	 *
	 * @param issuer
	 * @param paths
	 * @throws IllegalArgumentException throws exception if paths length is not 1 or 3, 1 for <strong>fromOidcLocationIssuer</strong>
	 * and 3 for the newly introduced <strong>fromIssuerLocation</strong> to support querying 3 different metadata provider endpoints
	 * @return Map<ProviderType, String> key-value map of provider with its request url
	 */
	private static Map<ProviderType, String> buildIssuerConfigurationUrls(String issuer, String... paths) {
		Assert.isTrue(paths.length != 1 || paths.length != 3, "paths length can either be 1 or 3");

		Map<ProviderType, String> providersUrl = new HashMap<>();

		URI issuerURI = URI.create(issuer);

		if (paths.length == 1) {
			providersUrl.put(ProviderType.OIDCV1,
					UriComponentsBuilder.fromUri(issuerURI).replacePath(issuerURI.getPath() + paths[0]).toUriString());
		} else {
			providersUrl.put(ProviderType.OIDC,
					UriComponentsBuilder.fromUri(issuerURI).replacePath(paths[0] + issuerURI.getPath()).toUriString());
			providersUrl.put(ProviderType.OIDCV1,
					UriComponentsBuilder.fromUri(issuerURI).replacePath(issuerURI.getPath() + paths[0]).toUriString());
			providersUrl.put(ProviderType.OAUTH2,
					UriComponentsBuilder.fromUri(issuerURI).replacePath(paths[1] + issuerURI.getPath()).toUriString());
		}

		return providersUrl;
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
