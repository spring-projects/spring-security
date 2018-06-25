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
package org.springframework.security.config.annotation.web.configuration;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link OAuth2ClientConfiguration}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientConfigurationTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void requestWhenAuthorizedClientFoundThenMethodArgumentResolved() throws Exception {
		String clientRegistrationId = "client1";
		String principalName = "user1";

		OAuth2AuthorizedClientService authorizedClientService = mock(OAuth2AuthorizedClientService.class);
		OAuth2AuthorizedClient authorizedClient = mock(OAuth2AuthorizedClient.class);
		when(authorizedClientService.loadAuthorizedClient(clientRegistrationId, principalName)).thenReturn(authorizedClient);

		OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
		when(authorizedClient.getAccessToken()).thenReturn(accessToken);

		OAuth2AuthorizedClientArgumentResolverConfig.AUTHORIZED_CLIENT_SERVICE = authorizedClientService;
		this.spring.register(OAuth2AuthorizedClientArgumentResolverConfig.class).autowire();

		this.mockMvc.perform(get("/authorized-client").with(user(principalName)))
			.andExpect(status().isOk())
			.andExpect(content().string("resolved"));
	}

	@EnableWebMvc
	@EnableWebSecurity
	static class OAuth2AuthorizedClientArgumentResolverConfig extends WebSecurityConfigurerAdapter {
		static OAuth2AuthorizedClientService AUTHORIZED_CLIENT_SERVICE;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
		}

		@RestController
		public class Controller {

			@GetMapping("/authorized-client")
			public String authorizedClient(@RegisteredOAuth2AuthorizedClient("client1") OAuth2AuthorizedClient authorizedClient) {
				return authorizedClient != null ? "resolved" : "not-resolved";
			}
		}

		@Bean
		public OAuth2AuthorizedClientService authorizedClientService() {
			return AUTHORIZED_CLIENT_SERVICE;
		}
	}

	// gh-5321
	@Test
	public void loadContextWhenOAuth2AuthorizedClientServiceRegisteredTwiceThenThrowNoUniqueBeanDefinitionException() {
		assertThatThrownBy(() -> this.spring.register(OAuth2AuthorizedClientServiceRegisteredTwiceConfig.class).autowire())
				.hasRootCauseInstanceOf(NoUniqueBeanDefinitionException.class)
				.hasMessageContaining("Expected single matching bean of type '" + OAuth2AuthorizedClientService.class.getName() +
					"' but found 2: authorizedClientService1,authorizedClientService2");
	}

	@EnableWebMvc
	@EnableWebSecurity
	static class OAuth2AuthorizedClientServiceRegisteredTwiceConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2Login();
			// @formatter:on
		}

		@Bean
		public ClientRegistrationRepository clientRegistrationRepository() {
			return mock(ClientRegistrationRepository.class);
		}

		@Bean
		public OAuth2AuthorizedClientService authorizedClientService1() {
			return mock(OAuth2AuthorizedClientService.class);
		}

		@Bean
		public OAuth2AuthorizedClientService authorizedClientService2() {
			return mock(OAuth2AuthorizedClientService.class);
		}
	}

	@Test
	public void loadContextWhenClientRegistrationRepositoryNotRegisteredThenThrowNoSuchBeanDefinitionException() {
		assertThatThrownBy(() -> this.spring.register(ClientRegistrationRepositoryNotRegisteredConfig.class).autowire())
				.hasRootCauseInstanceOf(NoSuchBeanDefinitionException.class)
				.hasMessageContaining("No qualifying bean of type '" + ClientRegistrationRepository.class.getName() + "' available");
	}

	@EnableWebMvc
	@EnableWebSecurity
	static class ClientRegistrationRepositoryNotRegisteredConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2Login();
			// @formatter:on
		}
	}

	@Test
	public void loadContextWhenClientRegistrationRepositoryRegisteredTwiceThenThrowNoUniqueBeanDefinitionException() {
		assertThatThrownBy(() -> this.spring.register(ClientRegistrationRepositoryRegisteredTwiceConfig.class).autowire())
				.hasRootCauseInstanceOf(NoUniqueBeanDefinitionException.class)
				.hasMessageContaining("Expected single matching bean of type '" + ClientRegistrationRepository.class.getName() +
						"' but found 2: clientRegistrationRepository1,clientRegistrationRepository2");
	}

	@EnableWebMvc
	@EnableWebSecurity
	static class ClientRegistrationRepositoryRegisteredTwiceConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2Login();
			// @formatter:on
		}

		@Bean
		public ClientRegistrationRepository clientRegistrationRepository1() {
			return mock(ClientRegistrationRepository.class);
		}

		@Bean
		public ClientRegistrationRepository clientRegistrationRepository2() {
			return mock(ClientRegistrationRepository.class);
		}

		@Bean
		public OAuth2AuthorizedClientService authorizedClientService() {
			return mock(OAuth2AuthorizedClientService.class);
		}
	}
}
