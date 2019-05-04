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


import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientInput;
import com.webauthn4j.data.extension.client.SupportedExtensionsExtensionClientInput;
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
import org.springframework.security.webauthn.WebAuthnProcessingFilter;
import org.springframework.security.webauthn.challenge.ChallengeRepository;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
		doThrow(new UsernameNotFoundException(null)).when(webAuthnUserDetailsService).loadUserByUsername(null);
		when(webAuthnUserDetailsService.loadUserByUsername(anyString())).thenReturn(mockUserDetails);
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
	public void attestationOptionsEndpointPath_with_anonymous_user_test() throws Exception {
		mvc = MockMvcBuilders.standaloneSetup()
				.addFilter(springSecurityFilterChain)
				.build();

		mvc
				.perform(get("/webauthn/attestation/options").with(anonymous()))
				.andExpect(unauthenticated())
				.andExpect(content().json("{\"rp\":{\"name\":\"example\",\"icon\":\"dummy\",\"id\":\"example.com\"},\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7},{\"type\":\"public-key\",\"alg\":-65535}],\"timeout\":10000,\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"userVerification\":\"preferred\"},\"extensions\":{\"exts\":true}}"))
				.andExpect(status().isOk());
	}

	@Test
	public void assertionOptionsEndpointPath_with_anonymous_user_test() throws Exception {
		mvc = MockMvcBuilders.standaloneSetup()
				.addFilter(springSecurityFilterChain)
				.build();

		mvc
				.perform(get("/webauthn/assertion/options").with(anonymous()))
				.andExpect(unauthenticated())
				.andExpect(content().json("{\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"timeout\":20000,\"rpId\":\"example.com\",\"allowCredentials\":[],\"extensions\":{\"appid\":\"\"}}"))
				.andExpect(status().isOk());
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

	@Test
	public void assertionOptionsEndpointPath_with_authenticated_user_test() throws Exception {
		mvc = MockMvcBuilders.standaloneSetup()
				.addFilter(springSecurityFilterChain)
				.build();

		mvc
				.perform(get("/webauthn/assertion/options").with(user("john")))
				.andExpect(authenticated())
				.andExpect(content().json("{\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"timeout\":20000,\"rpId\":\"example.com\",\"allowCredentials\":[{\"type\":\"public-key\",\"id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}],\"extensions\":{\"appid\":\"\"}}"))
				.andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {

		@Autowired
		private JsonConverter jsonConverter;

		@Override
		protected void configure(HttpSecurity http) throws Exception {

			// Authentication
			http.apply(webAuthnLogin())
					.rpId("example.com")
					.rpIcon("dummy")
					.rpName("example")
					.publicKeyCredParams()
						.addPublicKeyCredParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
						.addPublicKeyCredParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1)
					.and()
					.registrationTimeout(10000L)
					.authenticationTimeout(20000L)
					.registrationExtensions()
						.put(new SupportedExtensionsExtensionClientInput(true))
					.and()
					.authenticationExtensions()
						.put(new FIDOAppIDExtensionClientInput(""))
					.and()
					.usernameParameter("username")
					.passwordParameter("password")
					.credentialIdParameter("credentialId")
					.clientDataJSONParameter("clientDataJSON")
					.authenticatorDataParameter("authenticatorData")
					.signatureParameter("signature")
					.clientExtensionsJSONParameter("clientExtensionsJSON")
					.successForwardUrl("/")
					.failureForwardUrl("/login")
					.loginPage("/login")
					.attestationOptionsEndpoint()
						.processingUrl("/webauthn/attestation/options")
					.and()
					.assertionOptionsEndpoint()
						.processingUrl("/webauthn/assertion/options")
					.and()
					.jsonConverter(jsonConverter);

			// Authorization
			http.authorizeRequests()
					.antMatchers("/login").permitAll()
					.anyRequest().authenticated();
		}

		@Configuration
		static class BeanConfig {

			@Bean
			public WebAuthnUserDetailsService webAuthnUserDetailsService(){
				return mock(WebAuthnUserDetailsService.class);
			}

			@Bean
			public JsonConverter jsonConverter() {
				return new JsonConverter();
			}

			@Bean
			public ChallengeRepository challengeRepository() {
				ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
				when(challengeRepository.loadOrGenerateChallenge(any())).thenReturn(new DefaultChallenge("aFglXMZdQTKD4krvNzJBzA"));
				return challengeRepository;
			}

		}

	}
}
