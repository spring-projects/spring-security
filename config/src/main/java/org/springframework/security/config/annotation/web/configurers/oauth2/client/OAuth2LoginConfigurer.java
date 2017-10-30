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
import org.springframework.core.ResolvableType;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.jwt.JwtDecoderRegistry;
import org.springframework.security.oauth2.client.jwt.NimbusJwtDecoderRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DelegatingOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A security configurer for OAuth 2.0 / OpenID Connect 1.0 login.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public final class OAuth2LoginConfigurer<B extends HttpSecurityBuilder<B>> extends
	AbstractAuthenticationFilterConfigurer<B, OAuth2LoginConfigurer<B>, OAuth2LoginAuthenticationFilter> {

	private final AuthorizationEndpointConfig authorizationEndpointConfig = new AuthorizationEndpointConfig();
	private final TokenEndpointConfig tokenEndpointConfig = new TokenEndpointConfig();
	private final RedirectionEndpointConfig redirectionEndpointConfig = new RedirectionEndpointConfig();
	private final UserInfoEndpointConfig userInfoEndpointConfig = new UserInfoEndpointConfig();

	public OAuth2LoginConfigurer() {
		super();
	}

	public OAuth2LoginConfigurer<B> clients(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	public OAuth2LoginConfigurer<B> authorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.getBuilder().setSharedObject(OAuth2AuthorizedClientService.class, authorizedClientService);
		return this;
	}

	@Override
	public OAuth2LoginConfigurer<B> loginPage(String loginPage) {
		Assert.hasText(loginPage, "loginPage cannot be empty");
		return super.loginPage(loginPage);
	}

	public AuthorizationEndpointConfig authorizationEndpoint() {
		return this.authorizationEndpointConfig;
	}

	public class AuthorizationEndpointConfig {
		private String authorizationRequestBaseUri;
		private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

		private AuthorizationEndpointConfig() {
		}

		public AuthorizationEndpointConfig baseUri(String authorizationRequestBaseUri) {
			Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
			this.authorizationRequestBaseUri = authorizationRequestBaseUri;
			return this;
		}

		public AuthorizationEndpointConfig authorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
			Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
			this.authorizationRequestRepository = authorizationRequestRepository;
			return this;
		}

		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	public TokenEndpointConfig tokenEndpoint() {
		return this.tokenEndpointConfig;
	}

	public class TokenEndpointConfig {
		private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
		private JwtDecoderRegistry jwtDecoderRegistry;

		private TokenEndpointConfig() {
		}

		public TokenEndpointConfig accessTokenResponseClient(
			OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {

			Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
			this.accessTokenResponseClient = accessTokenResponseClient;
			return this;
		}

		public TokenEndpointConfig jwtDecoderRegistry(JwtDecoderRegistry jwtDecoderRegistry) {
			Assert.notNull(jwtDecoderRegistry, "jwtDecoderRegistry cannot be null");
			this.jwtDecoderRegistry = jwtDecoderRegistry;
			return this;
		}

		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	public RedirectionEndpointConfig redirectionEndpoint() {
		return this.redirectionEndpointConfig;
	}

	public class RedirectionEndpointConfig {
		private String authorizationResponseBaseUri;

		private RedirectionEndpointConfig() {
		}

		public RedirectionEndpointConfig baseUri(String authorizationResponseBaseUri) {
			Assert.hasText(authorizationResponseBaseUri, "authorizationResponseBaseUri cannot be empty");
			this.authorizationResponseBaseUri = authorizationResponseBaseUri;
			return this;
		}

		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	public UserInfoEndpointConfig userInfoEndpoint() {
		return this.userInfoEndpointConfig;
	}

	public class UserInfoEndpointConfig {
		private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
		private Map<String, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();
		private GrantedAuthoritiesMapper userAuthoritiesMapper;

		private UserInfoEndpointConfig() {
		}

		public UserInfoEndpointConfig userService(OAuth2UserService<OAuth2UserRequest, OAuth2User> userService) {
			Assert.notNull(userService, "userService cannot be null");
			this.userService = userService;
			return this;
		}

		public UserInfoEndpointConfig customUserType(Class<? extends OAuth2User> customUserType, String clientRegistrationId) {
			Assert.notNull(customUserType, "customUserType cannot be null");
			Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
			this.customUserTypes.put(clientRegistrationId, customUserType);
			return this;
		}

		public UserInfoEndpointConfig userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper) {
			Assert.notNull(userAuthoritiesMapper, "userAuthoritiesMapper cannot be null");
			this.userAuthoritiesMapper = userAuthoritiesMapper;
			return this;
		}

		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	@Override
	public void init(B http) throws Exception {
		OAuth2LoginAuthenticationFilter authenticationFilter =
			new OAuth2LoginAuthenticationFilter(
				OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI,
				this.getClientRegistrationRepository(),
				this.getAuthorizedClientService());
		this.setAuthenticationFilter(authenticationFilter);
		this.loginProcessingUrl(OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI);

		super.init(http);

		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient =
			this.tokenEndpointConfig.accessTokenResponseClient;
		if (accessTokenResponseClient == null) {
			accessTokenResponseClient = new NimbusAuthorizationCodeTokenResponseClient();
		}

		OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = this.userInfoEndpointConfig.userService;
		if (oauth2UserService == null) {
			if (!this.userInfoEndpointConfig.customUserTypes.isEmpty()) {
				List<OAuth2UserService<OAuth2UserRequest, OAuth2User>> userServices = new ArrayList<>();
				userServices.add(new CustomUserTypesOAuth2UserService(this.userInfoEndpointConfig.customUserTypes));
				userServices.add(new DefaultOAuth2UserService());
				oauth2UserService = new DelegatingOAuth2UserService<>(userServices);
			} else {
				oauth2UserService = new DefaultOAuth2UserService();
			}
		}

		JwtDecoderRegistry jwtDecoderRegistry = this.tokenEndpointConfig.jwtDecoderRegistry;
		if (jwtDecoderRegistry == null) {
			jwtDecoderRegistry = new NimbusJwtDecoderRegistry();
		}

		OAuth2LoginAuthenticationProvider oauth2LoginAuthenticationProvider =
			new OAuth2LoginAuthenticationProvider(accessTokenResponseClient, oauth2UserService);
		if (this.userInfoEndpointConfig.userAuthoritiesMapper != null) {
			oauth2LoginAuthenticationProvider.setAuthoritiesMapper(
				this.userInfoEndpointConfig.userAuthoritiesMapper);
		}
		http.authenticationProvider(this.postProcess(oauth2LoginAuthenticationProvider));

		OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService = new OidcUserService();
		OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider =
			new OidcAuthorizationCodeAuthenticationProvider(
				accessTokenResponseClient, oidcUserService, jwtDecoderRegistry);
		if (this.userInfoEndpointConfig.userAuthoritiesMapper != null) {
			oidcAuthorizationCodeAuthenticationProvider.setAuthoritiesMapper(
				this.userInfoEndpointConfig.userAuthoritiesMapper);
		}
		http.authenticationProvider(this.postProcess(oidcAuthorizationCodeAuthenticationProvider));

		this.initDefaultLoginFilter(http);
	}

	@Override
	public void configure(B http) throws Exception {
		String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
		if (authorizationRequestBaseUri == null) {
			authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
		}

		OAuth2AuthorizationRequestRedirectFilter authorizationRequestFilter = new OAuth2AuthorizationRequestRedirectFilter(
			authorizationRequestBaseUri, this.getClientRegistrationRepository());

		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			authorizationRequestFilter.setAuthorizationRequestRepository(
				this.authorizationEndpointConfig.authorizationRequestRepository);
		}
		http.addFilter(this.postProcess(authorizationRequestFilter));

		OAuth2LoginAuthenticationFilter authenticationFilter = this.getAuthenticationFilter();
		if (this.redirectionEndpointConfig.authorizationResponseBaseUri != null) {
			authenticationFilter.setFilterProcessesUrl(this.redirectionEndpointConfig.authorizationResponseBaseUri);
		}
		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			authenticationFilter.setAuthorizationRequestRepository(
				this.authorizationEndpointConfig.authorizationRequestRepository);
		}
		super.configure(http);
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl);
	}

	private ClientRegistrationRepository getClientRegistrationRepository() {
		ClientRegistrationRepository clientRegistrationRepository =
			this.getBuilder().getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = this.getClientRegistrationRepositoryBean();
			this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private ClientRegistrationRepository getClientRegistrationRepositoryBean() {
		return this.getBuilder().getSharedObject(ApplicationContext.class).getBean(ClientRegistrationRepository.class);
	}

	private OAuth2AuthorizedClientService getAuthorizedClientService() {
		OAuth2AuthorizedClientService authorizedClientService =
			this.getBuilder().getSharedObject(OAuth2AuthorizedClientService.class);
		if (authorizedClientService == null) {
			authorizedClientService = this.getAuthorizedClientServiceBean();
			this.getBuilder().setSharedObject(OAuth2AuthorizedClientService.class, authorizedClientService);
		}
		return authorizedClientService;
	}

	private OAuth2AuthorizedClientService getAuthorizedClientServiceBean() {
		return this.getBuilder().getSharedObject(ApplicationContext.class).getBean(OAuth2AuthorizedClientService.class);
	}

	private void initDefaultLoginFilter(B http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter == null || this.isCustomLoginPage()) {
			return;
		}

		Iterable<ClientRegistration> clientRegistrations = null;
		ClientRegistrationRepository clientRegistrationRepository = this.getClientRegistrationRepository();
		ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
		if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
			clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
		}
		if (clientRegistrations == null) {
			return;
		}

		String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri != null ?
			this.authorizationEndpointConfig.authorizationRequestBaseUri :
			OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
		Map<String, String> authenticationUrlToClientName = new HashMap<>();

		clientRegistrations.forEach(registration -> authenticationUrlToClientName.put(
			authorizationRequestBaseUri + "/" + registration.getRegistrationId(),
			registration.getClientName()));
		loginPageGeneratingFilter.setOauth2LoginEnabled(true);
		loginPageGeneratingFilter.setOauth2AuthenticationUrlToClientName(authenticationUrlToClientName);
		loginPageGeneratingFilter.setLoginPageUrl(this.getLoginPage());
		loginPageGeneratingFilter.setFailureUrl(this.getFailureUrl());
	}
}
