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

package org.springframework.security.webauthn.config.configurers;


import com.webauthn4j.test.TestDataUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.webauthn.WebAuthnDataConverter;
import org.springframework.security.webauthn.WebAuthnProcessingFilter;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeImpl;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeRepository;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Collection;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.webauthn.config.configurers.WebAuthnLoginConfigurer.webAuthnLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
public class WebAuthnLoginConfigurerSpringTest {

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	private MockMvc mvc;

	@Autowired
	private WebAuthnUserDetailsService webAuthnUserDetailsService;

	@SuppressWarnings("unchecked")
	@Before
	public void setup() {
		WebAuthnUserDetails mockUserDetails = mock(WebAuthnUserDetails.class);
		Collection authenticators = Collections.singletonList(TestDataUtil.createAuthenticator());
		when(mockUserDetails.getAuthenticators()).thenReturn(authenticators);
		when(mockUserDetails.getUserHandle()).thenReturn(new byte[32]);
		doThrow(new UsernameNotFoundException(null)).when(webAuthnUserDetailsService).loadWebAuthnUserByUsername(null);
		when(webAuthnUserDetailsService.loadWebAuthnUserByUsername(anyString())).thenReturn(mockUserDetails);
	}

	@Test
	public void configured_filter_test() {
		WebAuthnProcessingFilter webAuthnProcessingFilter = (WebAuthnProcessingFilter) springSecurityFilterChain.getFilterChains().get(0).getFilters().stream().filter(item -> item instanceof WebAuthnProcessingFilter).findFirst().orElse(null);
		assertThat(webAuthnProcessingFilter).isNotNull();
	}


	@Test
	public void rootPath_with_anonymous_user_test() throws Exception {
		mvc = MockMvcBuilders.standaloneSetup()
				.addFilter(springSecurityFilterChain)
				.build();

		mvc
				.perform(get("/").with(anonymous()))
				.andExpect(unauthenticated())
				.andExpect(status().is3xxRedirection());
	}

	@Test
	public void rootPath_with_authenticated_user_test() throws Exception {
		mvc = MockMvcBuilders.standaloneSetup()
				.defaultRequest(get("/").with(user("john")))
				.addFilter(springSecurityFilterChain)
				.build();

		mvc
				.perform(get("/"))
				.andExpect(authenticated())
				.andExpect(status().isNotFound());

	}

	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {

			// Authentication
			http.apply(webAuthnLogin())
					.usernameParameter("username")
					.passwordParameter("password")
					.credentialIdParameter("credentialId")
					.clientDataJSONParameter("clientDataJSON")
					.authenticatorDataParameter("authenticatorData")
					.signatureParameter("signature")
					.clientExtensionsJSONParameter("clientExtensionsJSON")
					.successForwardUrl("/")
					.failureForwardUrl("/login")
					.loginPage("/login");

			// Authorization
			http.authorizeRequests()
					.antMatchers("/login").permitAll()
					.anyRequest().authenticated();
		}

		@Configuration
		static class BeanConfig {

			@Bean
			public WebAuthnUserDetailsService webAuthnUserDetailsService() {
				return mock(WebAuthnUserDetailsService.class);
			}

			@Bean
			public WebAuthnDataConverter webAuthnDataConverter() {
				return new WebAuthnDataConverter();
			}

			@Bean
			public WebAuthnChallengeRepository challengeRepository() {
				WebAuthnChallengeRepository webAuthnChallengeRepository = mock(WebAuthnChallengeRepository.class);
				when(webAuthnChallengeRepository.loadOrGenerateChallenge(any())).thenReturn(new WebAuthnChallengeImpl("aFglXMZdQTKD4krvNzJBzA"));
				return webAuthnChallengeRepository;
			}

		}

	}
}
