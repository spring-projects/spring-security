/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.oauth2.client;

import org.junit.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link CommonOAuth2Provider}.
 *
 * @author Phillip Webb
 */
public class CommonOAuth2ProviderTests {

	private static final String DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}";

	@Test
	public void getBuilderWhenGoogleShouldHaveGoogleSettings() throws Exception {
		ClientRegistration registration = build(CommonOAuth2Provider.GOOGLE);
		ProviderDetails providerDetails = registration.getProviderDetails();
		assertThat(providerDetails.getAuthorizationUri())
			.isEqualTo("https://accounts.google.com/o/oauth2/v2/auth");
		assertThat(providerDetails.getTokenUri())
			.isEqualTo("https://www.googleapis.com/oauth2/v4/token");
		assertThat(providerDetails.getUserInfoEndpoint().getUri())
			.isEqualTo("https://www.googleapis.com/oauth2/v3/userinfo");
		assertThat(providerDetails.getUserInfoEndpoint().getUserNameAttributeName())
			.isEqualTo(IdTokenClaimNames.SUB);
		assertThat(providerDetails.getJwkSetUri())
			.isEqualTo("https://www.googleapis.com/oauth2/v3/certs");
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(registration.getAuthorizationGrantType())
			.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registration.getRedirectUriTemplate()).isEqualTo(DEFAULT_REDIRECT_URL);
		assertThat(registration.getScopes()).containsOnly("openid", "profile", "email");
		assertThat(registration.getClientName()).isEqualTo("Google");
		assertThat(registration.getRegistrationId()).isEqualTo("123");
	}

	@Test
	public void getBuilderWhenGitHubShouldHaveGitHubSettings() throws Exception {
		ClientRegistration registration = build(CommonOAuth2Provider.GITHUB);
		ProviderDetails providerDetails = registration.getProviderDetails();
		assertThat(providerDetails.getAuthorizationUri())
			.isEqualTo("https://github.com/login/oauth/authorize");
		assertThat(providerDetails.getTokenUri())
			.isEqualTo("https://github.com/login/oauth/access_token");
		assertThat(providerDetails.getUserInfoEndpoint().getUri())
			.isEqualTo("https://api.github.com/user");
		assertThat(providerDetails.getUserInfoEndpoint().getUserNameAttributeName())
			.isEqualTo("id");
		assertThat(providerDetails.getJwkSetUri()).isNull();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(registration.getAuthorizationGrantType())
			.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registration.getRedirectUriTemplate()).isEqualTo(DEFAULT_REDIRECT_URL);
		assertThat(registration.getScopes()).containsOnly("read:user");
		assertThat(registration.getClientName()).isEqualTo("GitHub");
		assertThat(registration.getRegistrationId()).isEqualTo("123");
	}

	@Test
	public void getBuilderWhenFacebookShouldHaveFacebookSettings() throws Exception {
		ClientRegistration registration = build(CommonOAuth2Provider.FACEBOOK);
		ProviderDetails providerDetails = registration.getProviderDetails();
		assertThat(providerDetails.getAuthorizationUri())
			.isEqualTo("https://www.facebook.com/v2.8/dialog/oauth");
		assertThat(providerDetails.getTokenUri())
			.isEqualTo("https://graph.facebook.com/v2.8/oauth/access_token");
		assertThat(providerDetails.getUserInfoEndpoint().getUri())
			.isEqualTo("https://graph.facebook.com/me?fields=id,name,email");
		assertThat(providerDetails.getUserInfoEndpoint().getUserNameAttributeName())
			.isEqualTo("id");
		assertThat(providerDetails.getJwkSetUri()).isNull();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.POST);
		assertThat(registration.getAuthorizationGrantType())
			.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registration.getRedirectUriTemplate()).isEqualTo(DEFAULT_REDIRECT_URL);
		assertThat(registration.getScopes()).containsOnly("public_profile", "email");
		assertThat(registration.getClientName()).isEqualTo("Facebook");
		assertThat(registration.getRegistrationId()).isEqualTo("123");
	}

	@Test
	public void getBuilderWhenOktaShouldHaveOktaSettings() throws Exception {
		ClientRegistration registration = builder(CommonOAuth2Provider.OKTA)
			.authorizationUri("https://example.com/auth")
			.tokenUri("https://example.com/token")
			.userInfoUri("https://example.com/info")
			.jwkSetUri("https://example.com/jwkset").build();
		ProviderDetails providerDetails = registration.getProviderDetails();
		assertThat(providerDetails.getAuthorizationUri())
			.isEqualTo("https://example.com/auth");
		assertThat(providerDetails.getTokenUri()).isEqualTo("https://example.com/token");
		assertThat(providerDetails.getUserInfoEndpoint().getUri()).isEqualTo("https://example.com/info");
		assertThat(providerDetails.getUserInfoEndpoint().getUserNameAttributeName())
			.isEqualTo(IdTokenClaimNames.SUB);
		assertThat(providerDetails.getJwkSetUri()).isEqualTo("https://example.com/jwkset");
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(registration.getAuthorizationGrantType())
			.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registration.getRedirectUriTemplate()).isEqualTo(DEFAULT_REDIRECT_URL);
		assertThat(registration.getScopes()).containsOnly("openid", "profile", "email");
		assertThat(registration.getClientName()).isEqualTo("Okta");
		assertThat(registration.getRegistrationId()).isEqualTo("123");
	}

	private ClientRegistration build(CommonOAuth2Provider provider) {
		return builder(provider).build();
	}

	private ClientRegistration.Builder builder(CommonOAuth2Provider provider) {
		return provider.getBuilder("123")
			.clientId("abcd")
			.clientSecret("secret");
	}

}
