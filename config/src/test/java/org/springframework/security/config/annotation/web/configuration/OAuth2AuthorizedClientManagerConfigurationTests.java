/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.oauth2.client.AuthorizationCodeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.PasswordOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

/**
 * Tests for {@link OAuth2ClientConfiguration.OAuth2AuthorizedClientManagerConfiguration}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizedClientManagerConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private OAuth2AuthorizedClientManager authorizedClientManager;

	@Autowired(required = false)
	private AuthorizationCodeOAuth2AuthorizedClientProvider authorizationCodeAuthorizedClientProvider;

	@Autowired(required = false)
	private RefreshTokenOAuth2AuthorizedClientProvider refreshTokenAuthorizedClientProvider;

	@Autowired(required = false)
	private ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialsAuthorizedClientProvider;

	@Autowired(required = false)
	private PasswordOAuth2AuthorizedClientProvider passwordAuthorizedClientProvider;

	@Test
	public void loadContextWhenCustomRestOperationsThenConfigured() {
		this.spring.register(CustomRestOperationsConfig.class).autowire();
		assertThat(this.authorizedClientManager).isNotNull();
	}

	@Test
	public void loadContextWhenCustomAuthorizedClientProvidersThenConfigured() {
		this.spring.register(CustomAuthorizedClientProvidersConfig.class).autowire();
		assertThat(this.authorizedClientManager).isNotNull();
	}

	@Configuration
	@EnableWebSecurity
	static class CustomRestOperationsConfig extends OAuth2ClientBaseConfig {

		// TODO This needs to be autoconfigured in OAuth2LoginConfigurer and
		// OAuth2ClientConfigurer
		@Bean
		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient() {
			DefaultAuthorizationCodeTokenResponseClient tokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
			tokenResponseClient.setRestOperations(restOperations());
			return spy(tokenResponseClient);
		}

		@Bean
		OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenTokenResponseClient() {
			DefaultRefreshTokenTokenResponseClient tokenResponseClient = new DefaultRefreshTokenTokenResponseClient();
			tokenResponseClient.setRestOperations(restOperations());
			return spy(tokenResponseClient);
		}

		@Bean
		OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient() {
			DefaultClientCredentialsTokenResponseClient tokenResponseClient = new DefaultClientCredentialsTokenResponseClient();
			tokenResponseClient.setRestOperations(restOperations());
			return spy(tokenResponseClient);
		}

		@Bean
		OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> passwordTokenResponseClient() {
			DefaultPasswordTokenResponseClient tokenResponseClient = new DefaultPasswordTokenResponseClient();
			tokenResponseClient.setRestOperations(restOperations());
			return spy(tokenResponseClient);
		}

		// NOTE: This is autoconfigured in OAuth2LoginConfigurer and
		// OAuth2ClientConfigurer
		@Bean
		OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
			DefaultOAuth2UserService userService = new DefaultOAuth2UserService();
			userService.setRestOperations(restOperations());
			return spy(userService);
		}

		// NOTE: This is autoconfigured in OAuth2LoginConfigurer and
		// OAuth2ClientConfigurer
		@Bean
		OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
			OidcUserService userService = new OidcUserService();
			userService.setOauth2UserService(oauth2UserService());
			return spy(userService);
		}

		@Bean
		RestOperations restOperations() {
			// Minimum required configuration
			RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(),
					new OAuth2AccessTokenResponseHttpMessageConverter(), new MappingJackson2HttpMessageConverter()));
			restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

			// TODO Add custom configuration, eg. Proxy, TLS, etc

			return spy(restTemplate);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomAuthorizedClientProvidersConfig extends OAuth2ClientBaseConfig {

		@Bean
		AuthorizationCodeOAuth2AuthorizedClientProvider authorizationCodeProvider() {
			return mock(AuthorizationCodeOAuth2AuthorizedClientProvider.class);
		}

		@Bean
		RefreshTokenOAuth2AuthorizedClientProvider refreshTokenProvider() {
			return mock(RefreshTokenOAuth2AuthorizedClientProvider.class);
		}

		@Bean
		ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialsProvider() {
			return mock(ClientCredentialsOAuth2AuthorizedClientProvider.class);
		}

		@Bean
		PasswordOAuth2AuthorizedClientProvider passwordProvider() {
			return mock(PasswordOAuth2AuthorizedClientProvider.class);
		}

	}

	abstract static class OAuth2ClientBaseConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests(authorize ->
					authorize.anyRequest().authenticated())
				.oauth2Login(Customizer.withDefaults())
				.oauth2Client(Customizer.withDefaults());
			return http.build();
			// @formatter:on
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return mock(ClientRegistrationRepository.class);
		}

		@Bean
		OAuth2AuthorizedClientRepository authorizedClientRepository() {
			return mock(OAuth2AuthorizedClientRepository.class);
		}

	}

}
