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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.test.SpringTestContext;
import org.springframework.security.oauth2.server.authorization.test.SpringTestContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OpenID Connect 1.0 Provider Configuration endpoint.
 *
 * @author Sahariar Alam Khandoker
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
@ExtendWith(SpringTestContextExtension.class)
public class OidcProviderConfigurationTests {

	private static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";

	private static final String ISSUER = "https://example.com";

	public final SpringTestContext spring = new SpringTestContext();

	@Autowired
	private AuthorizationServerSettings authorizationServerSettings;

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenConfigurationRequestAndIssuerSetThenReturnDefaultConfigurationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		this.mvc.perform(get(ISSUER.concat(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI)))
			.andExpect(status().is2xxSuccessful())
			.andExpectAll(defaultConfigurationMatchers(ISSUER));
	}

	@Test
	public void requestWhenConfigurationRequestIncludesIssuerPathThenConfigurationResponseHasIssuerPath()
			throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithMultipleIssuersAllowed.class).autowire();

		String issuer = "https://example.com:8443/issuer1";
		this.mvc.perform(get(issuer.concat(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI)))
			.andExpect(status().is2xxSuccessful())
			.andExpectAll(defaultConfigurationMatchers(issuer));

		issuer = "https://example.com:8443/path1/issuer2";
		this.mvc.perform(get(issuer.concat(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI)))
			.andExpect(status().is2xxSuccessful())
			.andExpectAll(defaultConfigurationMatchers(issuer));

		issuer = "https://example.com:8443/path1/path2/issuer3";
		this.mvc.perform(get(issuer.concat(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI)))
			.andExpect(status().is2xxSuccessful())
			.andExpectAll(defaultConfigurationMatchers(issuer));
	}

	// gh-632
	@Test
	public void requestWhenConfigurationRequestAndUserAuthenticatedThenReturnConfigurationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		this.mvc.perform(get(ISSUER.concat(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI)).with(user("user")))
			.andExpect(status().is2xxSuccessful())
			.andExpectAll(defaultConfigurationMatchers(ISSUER));
	}

	// gh-616
	@Test
	public void requestWhenConfigurationRequestAndConfigurationCustomizerSetThenReturnCustomConfigurationResponse()
			throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithProviderConfigurationCustomizer.class).autowire();

		this.mvc.perform(get(ISSUER.concat(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI)))
			.andExpect(status().is2xxSuccessful())
			.andExpect(jsonPath(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED,
					hasItems(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL)));
	}

	@Test
	public void requestWhenConfigurationRequestAndClientRegistrationEnabledThenConfigurationResponseIncludesRegistrationEndpoint()
			throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithClientRegistrationEnabled.class).autowire();

		this.mvc.perform(get(ISSUER.concat(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI)))
			.andExpect(status().is2xxSuccessful())
			.andExpectAll(defaultConfigurationMatchers(ISSUER))
			.andExpect(jsonPath("$.registration_endpoint")
				.value(ISSUER.concat(this.authorizationServerSettings.getOidcClientRegistrationEndpoint())));
	}

	private ResultMatcher[] defaultConfigurationMatchers(String issuer) {
		// @formatter:off
		return new ResultMatcher[] {
				jsonPath("issuer").value(issuer),
				jsonPath("authorization_endpoint").value(issuer.concat(this.authorizationServerSettings.getAuthorizationEndpoint())),
				jsonPath("token_endpoint").value(issuer.concat(this.authorizationServerSettings.getTokenEndpoint())),
				jsonPath("$.token_endpoint_auth_methods_supported[0]").value(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()),
				jsonPath("$.token_endpoint_auth_methods_supported[1]").value(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()),
				jsonPath("$.token_endpoint_auth_methods_supported[2]").value(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()),
				jsonPath("$.token_endpoint_auth_methods_supported[3]").value(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue()),
				jsonPath("jwks_uri").value(issuer.concat(this.authorizationServerSettings.getJwkSetEndpoint())),
				jsonPath("userinfo_endpoint").value(issuer.concat(this.authorizationServerSettings.getOidcUserInfoEndpoint())),
				jsonPath("end_session_endpoint").value(issuer.concat(this.authorizationServerSettings.getOidcLogoutEndpoint())),
				jsonPath("response_types_supported").value(OAuth2AuthorizationResponseType.CODE.getValue()),
				jsonPath("$.grant_types_supported[0]").value(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				jsonPath("$.grant_types_supported[1]").value(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()),
				jsonPath("$.grant_types_supported[2]").value(AuthorizationGrantType.REFRESH_TOKEN.getValue()),
				jsonPath("revocation_endpoint").value(issuer.concat(this.authorizationServerSettings.getTokenRevocationEndpoint())),
				jsonPath("$.revocation_endpoint_auth_methods_supported[0]").value(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()),
				jsonPath("$.revocation_endpoint_auth_methods_supported[1]").value(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()),
				jsonPath("$.revocation_endpoint_auth_methods_supported[2]").value(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()),
				jsonPath("$.revocation_endpoint_auth_methods_supported[3]").value(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue()),
				jsonPath("introspection_endpoint").value(issuer.concat(this.authorizationServerSettings.getTokenIntrospectionEndpoint())),
				jsonPath("$.introspection_endpoint_auth_methods_supported[0]").value(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()),
				jsonPath("$.introspection_endpoint_auth_methods_supported[1]").value(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()),
				jsonPath("$.introspection_endpoint_auth_methods_supported[2]").value(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()),
				jsonPath("$.introspection_endpoint_auth_methods_supported[3]").value(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue()),
				jsonPath("$.code_challenge_methods_supported[0]").value("S256"),
				jsonPath("subject_types_supported").value("public"),
				jsonPath("id_token_signing_alg_values_supported").value(SignatureAlgorithm.RS256.getName()),
				jsonPath("scopes_supported").value(OidcScopes.OPENID)
		};
		// @formatter:on
	}

	@Test
	public void loadContextWhenIssuerNotValidUrlThenThrowException() {
		assertThatExceptionOfType(BeanCreationException.class).isThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithInvalidIssuerUrl.class).autowire());
	}

	@Test
	public void loadContextWhenIssuerNotValidUriThenThrowException() {
		assertThatExceptionOfType(BeanCreationException.class).isThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithInvalidIssuerUri.class).autowire());
	}

	@Test
	public void loadContextWhenIssuerWithQueryThenThrowException() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> this.spring.register(AuthorizationServerConfigurationWithIssuerQuery.class).autowire());
	}

	@Test
	public void loadContextWhenIssuerWithFragmentThenThrowException() {
		assertThatExceptionOfType(BeanCreationException.class).isThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerFragment.class).autowire());
	}

	@Test
	public void loadContextWhenIssuerWithQueryAndFragmentThenThrowException() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> this.spring.register(AuthorizationServerConfigurationWithIssuerQueryAndFragment.class)
				.autowire());
	}

	@Test
	public void loadContextWhenIssuerWithEmptyQueryThenThrowException() {
		assertThatExceptionOfType(BeanCreationException.class).isThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerEmptyQuery.class).autowire());
	}

	@Test
	public void loadContextWhenIssuerWithEmptyFragmentThenThrowException() {
		assertThatExceptionOfType(BeanCreationException.class).isThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerEmptyFragment.class).autowire());
	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfiguration {

		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer
				.authorizationServer();
			// @formatter:off
			http
				.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
				.with(authorizationServerConfigurer, (authorizationServer) ->
					authorizationServer
						.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
			return new InMemoryRegisteredClientRepository(registeredClient);
		}

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return new ImmutableJWKSet<>(new JWKSet(TestJwks.DEFAULT_RSA_JWK));
		}

		@Bean
		JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER).build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithMultipleIssuersAllowed extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().multipleIssuersAllowed(true).build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithProviderConfigurationCustomizer
			extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
					OAuth2AuthorizationServerConfigurer.authorizationServer();
			http
					.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
					.with(authorizationServerConfigurer, (authorizationServer) ->
							authorizationServer
									.oidc((oidc) ->
											oidc.providerConfigurationEndpoint((providerConfigurationEndpoint) ->
													providerConfigurationEndpoint
															.providerConfigurationCustomizer(providerConfigurationCustomizer())))
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		private Consumer<OidcProviderConfiguration.Builder> providerConfigurationCustomizer() {
			return (providerConfiguration) -> providerConfiguration.scope(OidcScopes.PROFILE).scope(OidcScopes.EMAIL);
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithClientRegistrationEnabled
			extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
					OAuth2AuthorizationServerConfigurer.authorizationServer();
			http
					.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
					.with(authorizationServerConfigurer, (authorizationServer) ->
							authorizationServer
									.oidc((oidc) ->
											oidc.clientRegistrationEndpoint(Customizer.withDefaults())
									)
					);
			return http.build();
		}
		// @formatter:on

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithInvalidIssuerUrl extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer("urn:example").build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithInvalidIssuerUri extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer("https://not a valid uri").build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithIssuerQuery extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER + "?param=value").build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithIssuerFragment extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER + "#fragment").build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithIssuerQueryAndFragment extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER + "?param=value#fragment").build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithIssuerEmptyQuery extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER + "?").build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithIssuerEmptyFragment extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER + "#").build();
		}

	}

}
