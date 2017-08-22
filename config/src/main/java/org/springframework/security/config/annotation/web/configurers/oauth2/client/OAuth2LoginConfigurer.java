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
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeRequestRedirectFilter;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestVariablesExtractor;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.client.authentication.AuthorizationCodeRequestRedirectFilter.CLIENT_ALIAS_URI_VARIABLE_NAME;

/**
 * @author Joe Grandja
 */
public final class OAuth2LoginConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<OAuth2LoginConfigurer<H>, H> {

	private final AuthorizationCodeRequestRedirectFilterConfigurer authorizationCodeRequestRedirectFilterConfigurer;
	private final AuthorizationCodeAuthenticationFilterConfigurer authorizationCodeAuthenticationFilterConfigurer;
	private final AuthorizationEndpointConfig authorizationEndpointConfig;
	private final TokenEndpointConfig tokenEndpointConfig;
	private final RedirectionEndpointConfig redirectionEndpointConfig;
	private final UserInfoEndpointConfig userInfoEndpointConfig;

	public OAuth2LoginConfigurer() {
		this.authorizationCodeRequestRedirectFilterConfigurer = new AuthorizationCodeRequestRedirectFilterConfigurer<>();
		this.authorizationCodeAuthenticationFilterConfigurer = new AuthorizationCodeAuthenticationFilterConfigurer<>();
		this.authorizationEndpointConfig = new AuthorizationEndpointConfig();
		this.tokenEndpointConfig = new TokenEndpointConfig();
		this.redirectionEndpointConfig = new RedirectionEndpointConfig();
		this.userInfoEndpointConfig = new UserInfoEndpointConfig();
	}

	public OAuth2LoginConfigurer<H> clients(ClientRegistration... clientRegistrations) {
		Assert.notEmpty(clientRegistrations, "clientRegistrations cannot be empty");
		return this.clients(new InMemoryClientRegistrationRepository(Arrays.asList(clientRegistrations)));
	}

	public OAuth2LoginConfigurer<H> clients(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notEmpty(clientRegistrationRepository.getRegistrations(), "clientRegistrationRepository cannot be empty");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	public OAuth2LoginConfigurer<H> userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper) {
		Assert.notNull(userAuthoritiesMapper, "userAuthoritiesMapper cannot be null");
		this.authorizationCodeAuthenticationFilterConfigurer.userAuthoritiesMapper(userAuthoritiesMapper);
		return this;
	}

	public OAuth2LoginConfigurer<H> successHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authorizationCodeAuthenticationFilterConfigurer.successHandler(authenticationSuccessHandler);
		return this;
	}

	public OAuth2LoginConfigurer<H> failureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authorizationCodeAuthenticationFilterConfigurer.failureHandler(authenticationFailureHandler);
		return this;
	}

	public AuthorizationEndpointConfig authorizationEndpoint() {
		return this.authorizationEndpointConfig;
	}

	public class AuthorizationEndpointConfig {

		private AuthorizationEndpointConfig() {
		}

		public AuthorizationEndpointConfig authorizationRequestBuilder(AuthorizationRequestUriBuilder authorizationRequestBuilder) {
			Assert.notNull(authorizationRequestBuilder, "authorizationRequestBuilder cannot be null");
			OAuth2LoginConfigurer.this.authorizationCodeRequestRedirectFilterConfigurer.authorizationRequestBuilder(authorizationRequestBuilder);
			return this;
		}

		public <R extends RequestMatcher & RequestVariablesExtractor> AuthorizationEndpointConfig requestMatcher(R authorizationRequestMatcher) {
			Assert.notNull(authorizationRequestMatcher, "authorizationRequestMatcher cannot be null");
			OAuth2LoginConfigurer.this.authorizationCodeRequestRedirectFilterConfigurer.authorizationRequestMatcher(authorizationRequestMatcher);
			return this;
		}

		public OAuth2LoginConfigurer<H> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	public TokenEndpointConfig tokenEndpoint() {
		return this.tokenEndpointConfig;
	}

	public class TokenEndpointConfig {

		private TokenEndpointConfig() {
		}

		public TokenEndpointConfig authorizationCodeTokenExchanger(
			AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger) {

			Assert.notNull(authorizationCodeTokenExchanger, "authorizationCodeTokenExchanger cannot be null");
			OAuth2LoginConfigurer.this.authorizationCodeAuthenticationFilterConfigurer.authorizationCodeTokenExchanger(authorizationCodeTokenExchanger);
			return this;
		}

		public OAuth2LoginConfigurer<H> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	public RedirectionEndpointConfig redirectionEndpoint() {
		return this.redirectionEndpointConfig;
	}

	public class RedirectionEndpointConfig {

		private RedirectionEndpointConfig() {
		}

		public <R extends RequestMatcher & RequestVariablesExtractor> RedirectionEndpointConfig requestMatcher(R authorizationResponseMatcher) {
			Assert.notNull(authorizationResponseMatcher, "authorizationResponseMatcher cannot be null");
			OAuth2LoginConfigurer.this.authorizationCodeAuthenticationFilterConfigurer.authorizationResponseMatcher(authorizationResponseMatcher);
			return this;
		}

		public OAuth2LoginConfigurer<H> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	public UserInfoEndpointConfig userInfoEndpoint() {
		return this.userInfoEndpointConfig;
	}

	public class UserInfoEndpointConfig {

		private UserInfoEndpointConfig() {
		}

		public UserInfoEndpointConfig userInfoService(OAuth2UserService userInfoService) {
			Assert.notNull(userInfoService, "userInfoService cannot be null");
			OAuth2LoginConfigurer.this.authorizationCodeAuthenticationFilterConfigurer.userInfoService(userInfoService);
			return this;
		}

		public UserInfoEndpointConfig customUserType(Class<? extends OAuth2User> customUserType, URI userInfoUri) {
			Assert.notNull(customUserType, "customUserType cannot be null");
			Assert.notNull(userInfoUri, "userInfoUri cannot be null");
			OAuth2LoginConfigurer.this.authorizationCodeAuthenticationFilterConfigurer.customUserType(customUserType, userInfoUri);
			return this;
		}

		public UserInfoEndpointConfig userNameAttributeName(String userNameAttributeName, URI userInfoUri) {
			Assert.hasText(userNameAttributeName, "userNameAttributeName cannot be empty");
			Assert.notNull(userInfoUri, "userInfoUri cannot be null");
			OAuth2LoginConfigurer.this.authorizationCodeAuthenticationFilterConfigurer.userNameAttributeName(userNameAttributeName, userInfoUri);
			return this;
		}

		public OAuth2LoginConfigurer<H> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	@Override
	public void init(H http) throws Exception {
		this.authorizationCodeRequestRedirectFilterConfigurer.setBuilder(http);
		this.authorizationCodeAuthenticationFilterConfigurer.setBuilder(http);

		this.authorizationCodeRequestRedirectFilterConfigurer.init(http);
		this.authorizationCodeAuthenticationFilterConfigurer.init(http);
		this.initDefaultLoginFilter(http);
	}

	@Override
	public void configure(H http) throws Exception {
		this.authorizationCodeRequestRedirectFilterConfigurer.configure(http);
		this.authorizationCodeAuthenticationFilterConfigurer.configure(http);
	}

	static <H extends HttpSecurityBuilder<H>> ClientRegistrationRepository getClientRegistrationRepository(H http) {
		ClientRegistrationRepository clientRegistrationRepository = http.getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = getDefaultClientRegistrationRepository(http);
			http.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private static <H extends HttpSecurityBuilder<H>> ClientRegistrationRepository getDefaultClientRegistrationRepository(H http) {
		return http.getSharedObject(ApplicationContext.class).getBean(ClientRegistrationRepository.class);
	}

	private void initDefaultLoginFilter(H http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null && !this.authorizationCodeAuthenticationFilterConfigurer.isCustomLoginPage()) {
			ClientRegistrationRepository clientRegistrationRepository = getClientRegistrationRepository(this.getBuilder());
			if (!CollectionUtils.isEmpty(clientRegistrationRepository.getRegistrations())) {
				String authorizationRequestBaseUri;
				RequestMatcher authorizationRequestMatcher = OAuth2LoginConfigurer.this.authorizationCodeRequestRedirectFilterConfigurer.getAuthorizationRequestMatcher();
				if (authorizationRequestMatcher != null && AntPathRequestMatcher.class.isAssignableFrom(authorizationRequestMatcher.getClass())) {
					String authorizationRequestPattern =  ((AntPathRequestMatcher)authorizationRequestMatcher).getPattern();
					String clientAliasTemplateVariable = "{" + CLIENT_ALIAS_URI_VARIABLE_NAME + "}";
					if (authorizationRequestPattern.endsWith(clientAliasTemplateVariable)) {
						authorizationRequestBaseUri = authorizationRequestPattern.substring(
							0, authorizationRequestPattern.length() - clientAliasTemplateVariable.length() - 1);
					} else {
						authorizationRequestBaseUri = authorizationRequestPattern;
					}
				} else {
					authorizationRequestBaseUri = AuthorizationCodeRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
				}

				Map<String, String> oauth2AuthenticationUrlToClientName = clientRegistrationRepository.getRegistrations().stream()
					.collect(Collectors.toMap(
						e -> authorizationRequestBaseUri + "/" + e.getClientAlias(),
						e -> e.getClientName()));
				loginPageGeneratingFilter.setOauth2LoginEnabled(true);
				loginPageGeneratingFilter.setOauth2AuthenticationUrlToClientName(oauth2AuthenticationUrlToClientName);
				loginPageGeneratingFilter.setLoginPageUrl(this.authorizationCodeAuthenticationFilterConfigurer.getLoginUrl());
				loginPageGeneratingFilter.setFailureUrl(this.authorizationCodeAuthenticationFilterConfigurer.getLoginFailureUrl());
			}
		}
	}
}
