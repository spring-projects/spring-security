/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.config.http;

import static org.assertj.core.api.Assertions.assertThat;

import org.assertj.core.util.Arrays;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import com.google.common.collect.Sets;

/**
 * Tests for {@link ClientRegistrationsBeanDefinitionParser}.
 *
 * @author Ruby Hartono
 */
public class ClientRegistrationsBeanDefinitionParserTests {
	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/ClientRegistrationsBeanDefinitionParserTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	private OAuth2AuthorizedClientService oauth2AuthorizedClientService;

	@Test
	public void multiClientRegistrationConfiguration() throws Exception {
		this.spring.configLocations(this.xml("MultiClientRegistration")).autowire();

		assertThat(clientRegistrationRepository).isInstanceOf(InMemoryClientRegistrationRepository.class);
		assertThat(oauth2AuthorizedClientService).isInstanceOf(InMemoryOAuth2AuthorizedClientService.class);

		ClientRegistration googleLogin = clientRegistrationRepository.findByRegistrationId("google-login");
		assertThat(googleLogin).isNotNull();
		assertThat(googleLogin.getRegistrationId()).isEqualTo("google-login");
		assertThat(googleLogin.getClientId()).isEqualTo("google-client-id");
		assertThat(googleLogin.getClientSecret()).isEqualTo("google-client-secret");
		assertThat(googleLogin.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(googleLogin.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(googleLogin.getRedirectUriTemplate()).isEqualTo("{baseUrl}/login/oauth2/code/{registrationId}");
		assertThat(googleLogin.getScopes())
				.isEqualTo(Sets.newLinkedHashSet(Arrays.asList("openid,profile,email".split(","))));
		assertThat(googleLogin.getClientName()).isEqualTo("Google");

		ProviderDetails googleProviderDetails = googleLogin.getProviderDetails();
		assertThat(googleProviderDetails).isNotNull();
		assertThat(googleProviderDetails.getAuthorizationUri())
				.isEqualTo("https://accounts.google.com/o/oauth2/v2/auth");
		assertThat(googleProviderDetails.getTokenUri()).isEqualTo("https://www.googleapis.com/oauth2/v4/token");
		assertThat(googleProviderDetails.getUserInfoEndpoint().getUri())
				.isEqualTo("https://www.googleapis.com/oauth2/v3/userinfo");
		assertThat(googleProviderDetails.getUserInfoEndpoint().getAuthenticationMethod())
				.isEqualTo(AuthenticationMethod.HEADER);
		assertThat(googleProviderDetails.getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("sub");
		assertThat(googleProviderDetails.getJwkSetUri()).isEqualTo("https://www.googleapis.com/oauth2/v3/certs");

		ClientRegistration githubLogin = clientRegistrationRepository.findByRegistrationId("github-login");
		assertThat(githubLogin).isNotNull();
		assertThat(githubLogin.getRegistrationId()).isEqualTo("github-login");
		assertThat(githubLogin.getClientId()).isEqualTo("github-client-id");
		assertThat(githubLogin.getClientSecret()).isEqualTo("github-client-secret");
		assertThat(githubLogin.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(githubLogin.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(githubLogin.getRedirectUriTemplate()).isEqualTo("{baseUrl}/login/oauth2/code/{registrationId}");
		assertThat(googleLogin.getScopes())
				.isEqualTo(Sets.newLinkedHashSet(Arrays.asList("openid,profile,email".split(","))));
		assertThat(githubLogin.getClientName()).isEqualTo("Github");

		ProviderDetails githubProviderDetails = githubLogin.getProviderDetails();
		assertThat(githubProviderDetails).isNotNull();
		assertThat(githubProviderDetails.getAuthorizationUri()).isEqualTo("https://github.com/login/oauth/authorize");
		assertThat(githubProviderDetails.getTokenUri()).isEqualTo("https://github.com/login/oauth/access_token");
		assertThat(githubProviderDetails.getUserInfoEndpoint().getUri()).isEqualTo("https://api.github.com/user");
		assertThat(githubProviderDetails.getUserInfoEndpoint().getAuthenticationMethod())
				.isEqualTo(AuthenticationMethod.HEADER);
		assertThat(githubProviderDetails.getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("id");
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}
}
