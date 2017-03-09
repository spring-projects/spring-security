/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.config.annotation.web.configurers;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.ui.DefaultOAuth2LoginPageGeneratingFilter;
import org.springframework.security.oauth2.client.authorization.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserDetails;
import org.springframework.util.Assert;

import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.client.authentication.ui.AbstractLoginPageGeneratingFilter.ERROR_PARAMETER_NAME;
import static org.springframework.security.oauth2.client.authentication.ui.AbstractLoginPageGeneratingFilter.LOGOUT_PARAMETER_NAME;

/**
 * @author Joe Grandja
 */
public final class OAuth2LoginSecurityConfigurer<B extends HttpSecurityBuilder<B>> extends
		AbstractHttpConfigurer<OAuth2LoginSecurityConfigurer<B>, B> {

	private final AuthorizationRequestRedirectFilterConfigurer<B> authorizationRequestRedirectFilterConfigurer;

	private final AuthorizationCodeGrantFilterConfigurer<B> authorizationCodeGrantFilterConfigurer;

	private final UserInfoEndpointConfig userInfoEndpointConfig;

	private boolean loginPageFilterEnabled;


	public OAuth2LoginSecurityConfigurer() {
		this.authorizationRequestRedirectFilterConfigurer = new AuthorizationRequestRedirectFilterConfigurer<>();
		this.authorizationCodeGrantFilterConfigurer = new AuthorizationCodeGrantFilterConfigurer<>();
		this.userInfoEndpointConfig = new UserInfoEndpointConfig();
		this.loginPageFilterEnabled = true;
	}

	public OAuth2LoginSecurityConfigurer<B> clients(ClientRegistration... clientRegistrations) {
		Assert.notEmpty(clientRegistrations, "clientRegistrations cannot be empty");
		return clients(new InMemoryClientRegistrationRepository(Arrays.asList(clientRegistrations)));
	}

	public OAuth2LoginSecurityConfigurer<B> clients(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notEmpty(clientRegistrationRepository.getRegistrations(), "clientRegistrationRepository cannot be empty");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	public OAuth2LoginSecurityConfigurer<B> clientsPage(String clientsPage) {
		Assert.notNull(clientsPage, "clientsPage cannot be null");
		this.authorizationCodeGrantFilterConfigurer.clientsPage(clientsPage);
		this.loginPageFilterEnabled = false;
		return this;
	}

	public OAuth2LoginSecurityConfigurer<B> authorizationEndpoint(String authorizationUri) {
		Assert.notNull(authorizationUri, "authorizationUri cannot be null");
		this.authorizationRequestRedirectFilterConfigurer.authorizationProcessingUri(authorizationUri);
		return this;
	}

	public OAuth2LoginSecurityConfigurer<B> authorizationRequestBuilder(AuthorizationRequestUriBuilder authorizationRequestBuilder) {
		Assert.notNull(authorizationRequestBuilder, "authorizationRequestBuilder cannot be null");
		this.authorizationRequestRedirectFilterConfigurer.authorizationRequestBuilder(authorizationRequestBuilder);
		return this;
	}

	public OAuth2LoginSecurityConfigurer<B> authorizationCodeGrantTokenExchanger(
			AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> authorizationCodeGrantTokenExchanger) {

		Assert.notNull(authorizationCodeGrantTokenExchanger, "authorizationCodeGrantTokenExchanger cannot be null");
		this.authorizationCodeGrantFilterConfigurer.authorizationCodeGrantTokenExchanger(authorizationCodeGrantTokenExchanger);
		return this;
	}

	public UserInfoEndpointConfig userInfoEndpoint() {
		return this.userInfoEndpointConfig;
	}

	public final class UserInfoEndpointConfig {

		private UserInfoEndpointConfig() {
		}

		public OAuth2LoginSecurityConfigurer<B> userInfoService(UserInfoUserDetailsService userInfoService) {
			Assert.notNull(userInfoService, "userInfoService cannot be null");
			OAuth2LoginSecurityConfigurer.this.authorizationCodeGrantFilterConfigurer.userInfoUserDetailsService(userInfoService);
			return this.and();
		}

		public OAuth2LoginSecurityConfigurer<B> userInfoTypeMapping(Class<? extends OAuth2UserDetails> userInfoType, URI userInfoUri) {
			Assert.notNull(userInfoType, "userInfoType cannot be null");
			Assert.notNull(userInfoUri, "userInfoUri cannot be null");
			OAuth2LoginSecurityConfigurer.this.authorizationCodeGrantFilterConfigurer.userInfoTypeMapping(userInfoType, userInfoUri);
			return this.and();
		}

		public OAuth2LoginSecurityConfigurer<B> and() {
			return OAuth2LoginSecurityConfigurer.this;
		}
	}

	@Override
	public void init(B http) throws Exception {
		this.authorizationRequestRedirectFilterConfigurer.setBuilder(http);
		this.authorizationCodeGrantFilterConfigurer.setBuilder(http);

		this.authorizationRequestRedirectFilterConfigurer.init(http);
		this.authorizationCodeGrantFilterConfigurer.init(http);
	}

	@Override
	public void configure(B http) throws Exception {
		this.authorizationRequestRedirectFilterConfigurer.configure(http);
		this.authorizationCodeGrantFilterConfigurer.configure(http);
		this.initDefaultLoginFilter(http);
	}

	public static OAuth2LoginSecurityConfigurer<HttpSecurity> oauth2Login() {
		return new OAuth2LoginSecurityConfigurer<>();
	}

	protected static ClientRegistrationRepository getDefaultClientRegistrationRepository(ApplicationContext context) {
		Map<String, ClientRegistration> clientRegistrations = context.getBeansOfType(ClientRegistration.class);
		ClientRegistrationRepository clientRegistrationRepository = new InMemoryClientRegistrationRepository(
				clientRegistrations.values().stream().collect(Collectors.toList()));
		return clientRegistrationRepository;
	}

	private void initDefaultLoginFilter(B http) {
		if (!this.loginPageFilterEnabled) {
			return;
		}

		DefaultOAuth2LoginPageGeneratingFilter loginPageGeneratingFilter = new DefaultOAuth2LoginPageGeneratingFilter(
				this.getBuilder().getSharedObject(ClientRegistrationRepository.class));
		String clientsPage = this.authorizationCodeGrantFilterConfigurer.getClientsPage();
		loginPageGeneratingFilter.setLoginPageUrl(clientsPage);
		loginPageGeneratingFilter.setLogoutSuccessUrl(clientsPage + "?" + LOGOUT_PARAMETER_NAME);
		loginPageGeneratingFilter.setFailureUrl(clientsPage + "?" + ERROR_PARAMETER_NAME);
		loginPageGeneratingFilter.setAuthenticationUrl(
				this.authorizationRequestRedirectFilterConfigurer.getAuthorizationProcessingUri());
		loginPageGeneratingFilter.setLoginEnabled(true);

		http.addFilter(this.postProcess(loginPageGeneratingFilter));
	}
}
