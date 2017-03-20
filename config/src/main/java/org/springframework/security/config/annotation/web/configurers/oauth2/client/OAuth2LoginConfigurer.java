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
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeRequestRedirectFilter;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public final class OAuth2LoginConfigurer<B extends HttpSecurityBuilder<B>> extends
		AbstractHttpConfigurer<OAuth2LoginConfigurer<B>, B> {

	private final AuthorizationCodeRequestRedirectFilterConfigurer<B> authorizationCodeRequestRedirectFilterConfigurer;
	private final AuthorizationCodeAuthenticationFilterConfigurer<B> authorizationCodeAuthenticationFilterConfigurer;
	private final UserInfoEndpointConfig userInfoEndpointConfig;

	public OAuth2LoginConfigurer() {
		this.authorizationCodeRequestRedirectFilterConfigurer = new AuthorizationCodeRequestRedirectFilterConfigurer<>();
		this.authorizationCodeAuthenticationFilterConfigurer = new AuthorizationCodeAuthenticationFilterConfigurer<>();
		this.userInfoEndpointConfig = new UserInfoEndpointConfig();
	}

	public OAuth2LoginConfigurer<B> clients(ClientRegistration... clientRegistrations) {
		Assert.notEmpty(clientRegistrations, "clientRegistrations cannot be empty");
		return clients(new InMemoryClientRegistrationRepository(Arrays.asList(clientRegistrations)));
	}

	public OAuth2LoginConfigurer<B> clients(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notEmpty(clientRegistrationRepository.getRegistrations(), "clientRegistrationRepository cannot be empty");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	public OAuth2LoginConfigurer<B> authorizationRequestBuilder(AuthorizationRequestUriBuilder authorizationRequestBuilder) {
		Assert.notNull(authorizationRequestBuilder, "authorizationRequestBuilder cannot be null");
		this.authorizationCodeRequestRedirectFilterConfigurer.authorizationRequestBuilder(authorizationRequestBuilder);
		return this;
	}

	public OAuth2LoginConfigurer<B> authorizationCodeTokenExchanger(
			AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger) {

		Assert.notNull(authorizationCodeTokenExchanger, "authorizationCodeTokenExchanger cannot be null");
		this.authorizationCodeAuthenticationFilterConfigurer.authorizationCodeTokenExchanger(authorizationCodeTokenExchanger);
		return this;
	}

	public UserInfoEndpointConfig userInfoEndpoint() {
		return this.userInfoEndpointConfig;
	}

	public class UserInfoEndpointConfig {

		private UserInfoEndpointConfig() {
		}

		public OAuth2LoginConfigurer<B> userInfoService(OAuth2UserService userInfoService) {
			Assert.notNull(userInfoService, "userInfoService cannot be null");
			OAuth2LoginConfigurer.this.authorizationCodeAuthenticationFilterConfigurer.userInfoService(userInfoService);
			return this.and();
		}

		public OAuth2LoginConfigurer<B> userInfoTypeConverter(Converter<ClientHttpResponse, ? extends OAuth2User> userInfoConverter, URI userInfoUri) {
			Assert.notNull(userInfoConverter, "userInfoConverter cannot be null");
			Assert.notNull(userInfoUri, "userInfoUri cannot be null");
			OAuth2LoginConfigurer.this.authorizationCodeAuthenticationFilterConfigurer.userInfoTypeConverter(userInfoConverter, userInfoUri);
			return this.and();
		}

		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	@Override
	public void init(B http) throws Exception {
		this.authorizationCodeRequestRedirectFilterConfigurer.setBuilder(http);
		this.authorizationCodeAuthenticationFilterConfigurer.setBuilder(http);

		this.authorizationCodeRequestRedirectFilterConfigurer.init(http);
		this.authorizationCodeAuthenticationFilterConfigurer.init(http);
		this.initDefaultLoginFilter(http);
	}

	@Override
	public void configure(B http) throws Exception {
		this.authorizationCodeRequestRedirectFilterConfigurer.configure(http);
		this.authorizationCodeAuthenticationFilterConfigurer.configure(http);
	}

	static <B extends HttpSecurityBuilder<B>> ClientRegistrationRepository getClientRegistrationRepository(B http) {
		ClientRegistrationRepository clientRegistrationRepository = http.getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = getDefaultClientRegistrationRepository(http);
			http.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private static <B extends HttpSecurityBuilder<B>> ClientRegistrationRepository getDefaultClientRegistrationRepository(B http) {
		return http.getSharedObject(ApplicationContext.class).getBean(ClientRegistrationRepository.class);
	}

	private void initDefaultLoginFilter(B http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null && !this.authorizationCodeAuthenticationFilterConfigurer.isCustomLoginPage()) {
			ClientRegistrationRepository clientRegistrationRepository = getClientRegistrationRepository(this.getBuilder());
			if (!CollectionUtils.isEmpty(clientRegistrationRepository.getRegistrations())) {
				Map<String, String> oauth2AuthenticationUrlToClientName = clientRegistrationRepository.getRegistrations().stream()
					.collect(Collectors.toMap(e -> AuthorizationCodeRequestRedirectFilter.AUTHORIZATION_BASE_URI + "/" + e.getClientAlias(),
						e -> e.getClientName()));
				loginPageGeneratingFilter.setOauth2LoginEnabled(true);
				loginPageGeneratingFilter.setOauth2AuthenticationUrlToClientName(oauth2AuthenticationUrlToClientName);
				loginPageGeneratingFilter.setLoginPageUrl(this.authorizationCodeAuthenticationFilterConfigurer.getLoginUrl());
				loginPageGeneratingFilter.setFailureUrl(this.authorizationCodeAuthenticationFilterConfigurer.getLoginFailureUrl());
			}
		}
	}
}
