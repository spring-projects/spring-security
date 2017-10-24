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
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.NimbusAuthorizationCodeTokenExchanger;
import org.springframework.security.oauth2.client.authentication.jwt.JwtDecoderRegistry;
import org.springframework.security.oauth2.client.authentication.jwt.NimbusJwtDecoderRegistry;
import org.springframework.security.oauth2.client.authentication.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.authentication.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.authentication.userinfo.DelegatingOAuth2UserService;
import org.springframework.security.oauth2.client.authentication.userinfo.OAuth2UserAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.token.SecurityTokenRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.endpoint.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.client.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.oidc.client.authentication.userinfo.OidcUserAuthenticationProvider;
import org.springframework.security.oauth2.oidc.client.authentication.userinfo.OidcUserService;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
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

	private static final String DEFAULT_LOGIN_PROCESSING_URI = "/login/oauth2/authorize/code/*";
	private final AuthorizationEndpointConfig authorizationEndpointConfig = new AuthorizationEndpointConfig();
	private final TokenEndpointConfig tokenEndpointConfig = new TokenEndpointConfig();
	private final RedirectionEndpointConfig redirectionEndpointConfig = new RedirectionEndpointConfig();
	private final UserInfoEndpointConfig userInfoEndpointConfig = new UserInfoEndpointConfig();

	public OAuth2LoginConfigurer() {
		super(new OAuth2LoginAuthenticationFilter(DEFAULT_LOGIN_PROCESSING_URI), DEFAULT_LOGIN_PROCESSING_URI);
	}

	public OAuth2LoginConfigurer<B> clients(ClientRegistration... clientRegistrations) {
		Assert.notEmpty(clientRegistrations, "clientRegistrations cannot be empty");
		return this.clients(new InMemoryClientRegistrationRepository(Arrays.asList(clientRegistrations)));
	}

	public OAuth2LoginConfigurer<B> clients(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
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
		private AuthorizationRequestUriBuilder authorizationRequestUriBuilder;
		private AuthorizationRequestRepository authorizationRequestRepository;

		private AuthorizationEndpointConfig() {
		}

		public AuthorizationEndpointConfig baseUri(String authorizationRequestBaseUri) {
			Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
			this.authorizationRequestBaseUri = authorizationRequestBaseUri;
			return this;
		}

		public AuthorizationEndpointConfig authorizationRequestUriBuilder(AuthorizationRequestUriBuilder authorizationRequestUriBuilder) {
			Assert.notNull(authorizationRequestUriBuilder, "authorizationRequestUriBuilder cannot be null");
			this.authorizationRequestUriBuilder = authorizationRequestUriBuilder;
			return this;
		}

		public AuthorizationEndpointConfig authorizationRequestRepository(AuthorizationRequestRepository authorizationRequestRepository) {
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
		private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger;
		private SecurityTokenRepository<AccessToken> accessTokenRepository;
		private JwtDecoderRegistry jwtDecoderRegistry;

		private TokenEndpointConfig() {
		}

		public TokenEndpointConfig authorizationCodeTokenExchanger(
			AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger) {

			Assert.notNull(authorizationCodeTokenExchanger, "authorizationCodeTokenExchanger cannot be null");
			this.authorizationCodeTokenExchanger = authorizationCodeTokenExchanger;
			return this;
		}

		public TokenEndpointConfig accessTokenRepository(SecurityTokenRepository<AccessToken> accessTokenRepository) {
			Assert.notNull(accessTokenRepository, "accessTokenRepository cannot be null");
			this.accessTokenRepository = accessTokenRepository;
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
		private OAuth2UserService userService;
		private Map<URI, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();
		private GrantedAuthoritiesMapper userAuthoritiesMapper;

		private UserInfoEndpointConfig() {
		}

		public UserInfoEndpointConfig userService(OAuth2UserService userService) {
			Assert.notNull(userService, "userService cannot be null");
			this.userService = userService;
			return this;
		}

		public UserInfoEndpointConfig customUserType(Class<? extends OAuth2User> customUserType, URI userInfoUri) {
			Assert.notNull(customUserType, "customUserType cannot be null");
			Assert.notNull(userInfoUri, "userInfoUri cannot be null");
			this.customUserTypes.put(userInfoUri, customUserType);
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
		super.init(http);

		AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger =
			this.tokenEndpointConfig.authorizationCodeTokenExchanger;
		if (authorizationCodeTokenExchanger == null) {
			authorizationCodeTokenExchanger = new NimbusAuthorizationCodeTokenExchanger();
		}

		JwtDecoderRegistry jwtDecoderRegistry = this.tokenEndpointConfig.jwtDecoderRegistry;
		if (jwtDecoderRegistry == null) {
			jwtDecoderRegistry = new NimbusJwtDecoderRegistry();
		}

		AuthorizationCodeAuthenticationProvider oauth2AuthorizationCodeAuthenticationProvider =
			new AuthorizationCodeAuthenticationProvider(authorizationCodeTokenExchanger);
		if (this.tokenEndpointConfig.accessTokenRepository != null) {
			oauth2AuthorizationCodeAuthenticationProvider.setAccessTokenRepository(
				this.tokenEndpointConfig.accessTokenRepository);
		}
		http.authenticationProvider(this.postProcess(oauth2AuthorizationCodeAuthenticationProvider));

		OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider =
			new OidcAuthorizationCodeAuthenticationProvider(authorizationCodeTokenExchanger, jwtDecoderRegistry);
		if (this.tokenEndpointConfig.accessTokenRepository != null) {
			oidcAuthorizationCodeAuthenticationProvider.setAccessTokenRepository(
				this.tokenEndpointConfig.accessTokenRepository);
		}
		http.authenticationProvider(this.postProcess(oidcAuthorizationCodeAuthenticationProvider));

		OAuth2UserService userService = this.userInfoEndpointConfig.userService;
		if (userService == null) {
			if (!this.userInfoEndpointConfig.customUserTypes.isEmpty()) {
				List<OAuth2UserService> userServices = new ArrayList<>();
				userServices.add(new CustomUserTypesOAuth2UserService(this.userInfoEndpointConfig.customUserTypes));
				userServices.add(new DefaultOAuth2UserService());
				userService = new DelegatingOAuth2UserService(userServices);
			} else {
				userService = new DefaultOAuth2UserService();
			}
		}

		OAuth2UserAuthenticationProvider oauth2UserAuthenticationProvider =
			new OAuth2UserAuthenticationProvider(userService);
		if (this.userInfoEndpointConfig.userAuthoritiesMapper != null) {
			oauth2UserAuthenticationProvider.setAuthoritiesMapper(this.userInfoEndpointConfig.userAuthoritiesMapper);
		}
		http.authenticationProvider(this.postProcess(oauth2UserAuthenticationProvider));

		userService = this.userInfoEndpointConfig.userService;
		if (userService == null) {
			userService = new OidcUserService();
		}

		OidcUserAuthenticationProvider oidcUserAuthenticationProvider =
			new OidcUserAuthenticationProvider(userService);
		if (this.userInfoEndpointConfig.userAuthoritiesMapper != null) {
			oidcUserAuthenticationProvider.setAuthoritiesMapper(this.userInfoEndpointConfig.userAuthoritiesMapper);
		}
		http.authenticationProvider(this.postProcess(oidcUserAuthenticationProvider));

		this.initDefaultLoginFilter(http);
	}

	@Override
	public void configure(B http) throws Exception {
		String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
		if (authorizationRequestBaseUri == null) {
			authorizationRequestBaseUri = AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
		}

		AuthorizationRequestRedirectFilter authorizationRequestFilter = new AuthorizationRequestRedirectFilter(
			authorizationRequestBaseUri, this.getClientRegistrationRepository());
		if (this.authorizationEndpointConfig.authorizationRequestUriBuilder != null) {
			authorizationRequestFilter.setAuthorizationRequestUriBuilder(
				this.authorizationEndpointConfig.authorizationRequestUriBuilder);
		}
		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			authorizationRequestFilter.setAuthorizationRequestRepository(
				this.authorizationEndpointConfig.authorizationRequestRepository);
		}
		http.addFilter(this.postProcess(authorizationRequestFilter));

		OAuth2LoginAuthenticationFilter authorizationResponseFilter = this.getAuthenticationFilter();
		if (this.redirectionEndpointConfig.authorizationResponseBaseUri != null) {
			authorizationResponseFilter.setFilterProcessesUrl(this.redirectionEndpointConfig.authorizationResponseBaseUri);
		}
		authorizationResponseFilter.setClientRegistrationRepository(this.getClientRegistrationRepository());
		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			authorizationResponseFilter.setAuthorizationRequestRepository(
				this.authorizationEndpointConfig.authorizationRequestRepository);
		}
		super.configure(http);
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl);
	}

	private ClientRegistrationRepository getClientRegistrationRepository() {
		ClientRegistrationRepository clientRegistrationRepository = this.getBuilder().getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = this.getClientRegistrationRepositoryBean();
			this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private ClientRegistrationRepository getClientRegistrationRepositoryBean() {
		return this.getBuilder().getSharedObject(ApplicationContext.class).getBean(ClientRegistrationRepository.class);
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
			AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
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
