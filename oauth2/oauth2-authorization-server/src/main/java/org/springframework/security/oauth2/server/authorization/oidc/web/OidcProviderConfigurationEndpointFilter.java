/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.oidc.web;

import java.io.IOException;
import java.util.List;
import java.util.function.Consumer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcProviderConfigurationHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} that processes OpenID Provider Configuration Requests.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @since 7.0
 * @see OidcProviderConfiguration
 * @see AuthorizationServerSettings
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">4.1.
 * OpenID Provider Configuration Request</a>
 */
public final class OidcProviderConfigurationEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for OpenID Provider Configuration requests.
	 */
	private static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";

	private final RequestMatcher requestMatcher = createRequestMatcher();

	private final OidcProviderConfigurationHttpMessageConverter providerConfigurationHttpMessageConverter = new OidcProviderConfigurationHttpMessageConverter();

	private Consumer<OidcProviderConfiguration.Builder> providerConfigurationCustomizer = (providerConfiguration) -> {
	};

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OidcProviderConfiguration.Builder} allowing the ability to customize the
	 * claims of the OpenID Provider's configuration.
	 * @param providerConfigurationCustomizer the {@code Consumer} providing access to the
	 * {@link OidcProviderConfiguration.Builder}
	 */
	public void setProviderConfigurationCustomizer(
			Consumer<OidcProviderConfiguration.Builder> providerConfigurationCustomizer) {
		Assert.notNull(providerConfigurationCustomizer, "providerConfigurationCustomizer cannot be null");
		this.providerConfigurationCustomizer = providerConfigurationCustomizer;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
		String issuer = authorizationServerContext.getIssuer();
		AuthorizationServerSettings authorizationServerSettings = authorizationServerContext
			.getAuthorizationServerSettings();

		OidcProviderConfiguration.Builder providerConfiguration = OidcProviderConfiguration.builder()
			.issuer(issuer)
			.authorizationEndpoint(asUrl(issuer, authorizationServerSettings.getAuthorizationEndpoint()))
			.tokenEndpoint(asUrl(issuer, authorizationServerSettings.getTokenEndpoint()))
			.tokenEndpointAuthenticationMethods(clientAuthenticationMethods())
			.jwkSetUrl(asUrl(issuer, authorizationServerSettings.getJwkSetEndpoint()))
			.userInfoEndpoint(asUrl(issuer, authorizationServerSettings.getOidcUserInfoEndpoint()))
			.endSessionEndpoint(asUrl(issuer, authorizationServerSettings.getOidcLogoutEndpoint()))
			.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
			.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
			.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
			.grantType(AuthorizationGrantType.REFRESH_TOKEN.getValue())
			.grantType(AuthorizationGrantType.TOKEN_EXCHANGE.getValue())
			.tokenRevocationEndpoint(asUrl(issuer, authorizationServerSettings.getTokenRevocationEndpoint()))
			.tokenRevocationEndpointAuthenticationMethods(clientAuthenticationMethods())
			.tokenIntrospectionEndpoint(asUrl(issuer, authorizationServerSettings.getTokenIntrospectionEndpoint()))
			.tokenIntrospectionEndpointAuthenticationMethods(clientAuthenticationMethods())
			.codeChallengeMethod("S256")
			.tlsClientCertificateBoundAccessTokens(true)
			.dPoPSigningAlgorithms(dPoPSigningAlgorithms())
			.subjectType("public")
			.idTokenSigningAlgorithm(SignatureAlgorithm.RS256.getName())
			.scope(OidcScopes.OPENID);

		this.providerConfigurationCustomizer.accept(providerConfiguration);

		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.providerConfigurationHttpMessageConverter.write(providerConfiguration.build(), MediaType.APPLICATION_JSON,
				httpResponse);
	}

	private static RequestMatcher createRequestMatcher() {
		final RequestMatcher defaultRequestMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.GET, DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI);
		final RequestMatcher multipleIssuersRequestMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.GET, "/**" + DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI);
		return (request) -> AuthorizationServerContextHolder.getContext()
			.getAuthorizationServerSettings()
			.isMultipleIssuersAllowed() ? multipleIssuersRequestMatcher.matches(request)
					: defaultRequestMatcher.matches(request);
	}

	private static Consumer<List<String>> clientAuthenticationMethods() {
		return (authenticationMethods) -> {
			authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
			authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
			authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
			authenticationMethods.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
			authenticationMethods.add(ClientAuthenticationMethod.TLS_CLIENT_AUTH.getValue());
			authenticationMethods.add(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue());
		};
	}

	private static Consumer<List<String>> dPoPSigningAlgorithms() {
		return (algs) -> {
			algs.add(JwsAlgorithms.RS256);
			algs.add(JwsAlgorithms.RS384);
			algs.add(JwsAlgorithms.RS512);
			algs.add(JwsAlgorithms.PS256);
			algs.add(JwsAlgorithms.PS384);
			algs.add(JwsAlgorithms.PS512);
			algs.add(JwsAlgorithms.ES256);
			algs.add(JwsAlgorithms.ES384);
			algs.add(JwsAlgorithms.ES512);
		};
	}

	private static String asUrl(String issuer, String endpoint) {
		return UriComponentsBuilder.fromUriString(issuer).path(endpoint).build().toUriString();
	}

}
