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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticator;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantAuthenticator;
import org.springframework.security.oauth2.client.authentication.DelegatingAuthorizationGrantAuthenticator;
import org.springframework.security.oauth2.client.authentication.OAuth2UserAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.jwt.JwtDecoderRegistry;
import org.springframework.security.oauth2.client.authentication.jwt.nimbus.NimbusJwtDecoderRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.token.SecurityTokenRepository;
import org.springframework.security.oauth2.client.user.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.user.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.user.DelegatingOAuth2UserService;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationCodeAuthenticationFilter;
import org.springframework.security.oauth2.client.web.AuthorizationCodeRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.web.nimbus.NimbusAuthorizationCodeTokenExchanger;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.client.authentication.OidcAuthorizationCodeAuthenticator;
import org.springframework.security.oauth2.oidc.client.user.OidcUserService;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A security configurer for the Authorization Code Grant type.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public class AuthorizationCodeGrantConfigurer<B extends HttpSecurityBuilder<B>> extends
	AbstractHttpConfigurer<AuthorizationCodeGrantConfigurer<B>, B> {

	// ***** Authorization Request members
	private AuthorizationCodeRequestRedirectFilter authorizationRequestFilter;
	private RequestMatcher authorizationRequestMatcher;
	private AuthorizationRequestUriBuilder authorizationRequestBuilder;
	private AuthorizationRequestRepository authorizationRequestRepository;

	// ***** Authorization Response members
	private AuthorizationCodeAuthenticationFilter authorizationResponseFilter;
	private RequestMatcher authorizationResponseMatcher;
	private AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken> authorizationCodeAuthenticator;
	private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger;
	private SecurityTokenRepository<AccessToken> accessTokenRepository;
	private JwtDecoderRegistry jwtDecoderRegistry;
	private OAuth2UserService userService;
	private Map<URI, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();
	private GrantedAuthoritiesMapper userAuthoritiesMapper;

	public AuthorizationCodeGrantConfigurer<B> authorizationRequestMatcher(RequestMatcher authorizationRequestMatcher) {
		Assert.notNull(authorizationRequestMatcher, "authorizationRequestMatcher cannot be null");
		this.authorizationRequestMatcher = authorizationRequestMatcher;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> authorizationRequestBuilder(AuthorizationRequestUriBuilder authorizationRequestBuilder) {
		Assert.notNull(authorizationRequestBuilder, "authorizationRequestBuilder cannot be null");
		this.authorizationRequestBuilder = authorizationRequestBuilder;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> authorizationRequestRepository(AuthorizationRequestRepository authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> authorizationResponseMatcher(RequestMatcher authorizationResponseMatcher) {
		Assert.notNull(authorizationResponseMatcher, "authorizationResponseMatcher cannot be null");
		this.authorizationResponseMatcher = authorizationResponseMatcher;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> authorizationCodeAuthenticator(
		AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken> authorizationCodeAuthenticator) {

		Assert.notNull(authorizationCodeAuthenticator, "authorizationCodeAuthenticator cannot be null");
		this.authorizationCodeAuthenticator = authorizationCodeAuthenticator;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> authorizationCodeTokenExchanger(
		AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger) {

		Assert.notNull(authorizationCodeTokenExchanger, "authorizationCodeTokenExchanger cannot be null");
		this.authorizationCodeTokenExchanger = authorizationCodeTokenExchanger;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> accessTokenRepository(SecurityTokenRepository<AccessToken> accessTokenRepository) {
		Assert.notNull(accessTokenRepository, "accessTokenRepository cannot be null");
		this.accessTokenRepository = accessTokenRepository;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> jwtDecoderRegistry(JwtDecoderRegistry jwtDecoderRegistry) {
		Assert.notNull(jwtDecoderRegistry, "jwtDecoderRegistry cannot be null");
		this.jwtDecoderRegistry = jwtDecoderRegistry;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> userService(OAuth2UserService userService) {
		Assert.notNull(userService, "userService cannot be null");
		this.userService = userService;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> customUserType(Class<? extends OAuth2User> customUserType, URI userInfoUri) {
		Assert.notNull(customUserType, "customUserType cannot be null");
		Assert.notNull(userInfoUri, "userInfoUri cannot be null");
		this.customUserTypes.put(userInfoUri, customUserType);
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper) {
		Assert.notNull(userAuthoritiesMapper, "userAuthoritiesMapper cannot be null");
		this.userAuthoritiesMapper = userAuthoritiesMapper;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	@Override
	public final void init(B http) throws Exception {
		// *****************************************
		// ***** Initialize AuthenticationProvider's
		//
		// 	-> AuthorizationCodeAuthenticationProvider
		AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider =
			new AuthorizationCodeAuthenticationProvider(this.getAuthorizationCodeAuthenticator());
		if (this.accessTokenRepository != null) {
			authorizationCodeAuthenticationProvider.setAccessTokenRepository(this.accessTokenRepository);
		}
		http.authenticationProvider(this.postProcess(authorizationCodeAuthenticationProvider));

		// 	-> OAuth2UserAuthenticationProvider
		OAuth2UserAuthenticationProvider oauth2UserAuthenticationProvider =
			new OAuth2UserAuthenticationProvider(this.getUserService());
		if (this.userAuthoritiesMapper != null) {
			oauth2UserAuthenticationProvider.setAuthoritiesMapper(this.userAuthoritiesMapper);
		}
		http.authenticationProvider(this.postProcess(oauth2UserAuthenticationProvider));

		// *************************
		// ***** Initialize Filter's
		//
		// 	-> AuthorizationCodeRequestRedirectFilter
		this.authorizationRequestFilter = new AuthorizationCodeRequestRedirectFilter(
			this.getClientRegistrationRepository());
		if (this.authorizationRequestMatcher != null) {
			this.authorizationRequestFilter.setAuthorizationRequestMatcher(this.authorizationRequestMatcher);
		}
		if (this.authorizationRequestBuilder != null) {
			this.authorizationRequestFilter.setAuthorizationUriBuilder(this.authorizationRequestBuilder);
		}
		if (this.authorizationRequestRepository != null) {
			this.authorizationRequestFilter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
		}

		// 	-> AuthorizationCodeAuthenticationFilter
		this.authorizationResponseFilter = new AuthorizationCodeAuthenticationFilter();
		this.authorizationResponseFilter.setClientRegistrationRepository(this.getClientRegistrationRepository());
		if (this.authorizationResponseMatcher != null) {
			this.authorizationResponseFilter.setAuthorizationResponseMatcher(this.authorizationResponseMatcher);
		}
		if (this.authorizationRequestRepository != null) {
			this.authorizationResponseFilter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
		}
	}

	@Override
	public void configure(B http) throws Exception {
		http.addFilter(this.postProcess(this.authorizationRequestFilter));

		this.authorizationResponseFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
		SessionAuthenticationStrategy sessionAuthenticationStrategy = http.getSharedObject(SessionAuthenticationStrategy.class);
		if (sessionAuthenticationStrategy != null) {
			this.authorizationResponseFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
		}
		http.addFilter(this.postProcess(this.authorizationResponseFilter));
	}

	AuthorizationCodeRequestRedirectFilter getAuthorizationRequestFilter() {
		return this.authorizationRequestFilter;
	}

	RequestMatcher getAuthorizationRequestMatcher() {
		return this.authorizationRequestMatcher;
	}

	AuthorizationCodeAuthenticationFilter getAuthorizationResponseFilter() {
		return this.authorizationResponseFilter;
	}

	RequestMatcher getAuthorizationResponseMatcher() {
		return this.authorizationResponseMatcher;
	}

	AuthorizationRequestRepository getAuthorizationRequestRepository() {
		return this.authorizationRequestRepository;
	}

	private AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken> getAuthorizationCodeAuthenticator() {
		if (this.authorizationCodeAuthenticator == null) {
			List<AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken>> authenticators = new ArrayList<>();
			authenticators.add(new AuthorizationCodeAuthenticator(this.getAuthorizationCodeTokenExchanger()));
			authenticators.add(new OidcAuthorizationCodeAuthenticator(
				this.getAuthorizationCodeTokenExchanger(), this.getJwtDecoderRegistry()));
			this.authorizationCodeAuthenticator = new DelegatingAuthorizationGrantAuthenticator<>(authenticators);;
		}
		return this.authorizationCodeAuthenticator;
	}

	private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> getAuthorizationCodeTokenExchanger() {
		if (this.authorizationCodeTokenExchanger == null) {
			this.authorizationCodeTokenExchanger = new NimbusAuthorizationCodeTokenExchanger();
		}
		return this.authorizationCodeTokenExchanger;
	}

	private JwtDecoderRegistry getJwtDecoderRegistry() {
		if (this.jwtDecoderRegistry == null) {
			this.jwtDecoderRegistry = new NimbusJwtDecoderRegistry();
		}
		return this.jwtDecoderRegistry;
	}

	private OAuth2UserService getUserService() {
		if (this.userService == null) {
			List<OAuth2UserService> userServices = new ArrayList<>();
			userServices.add(new DefaultOAuth2UserService());
			userServices.add(new OidcUserService());
			if (!this.customUserTypes.isEmpty()) {
				userServices.add(new CustomUserTypesOAuth2UserService(this.customUserTypes));
			}
			this.userService = new DelegatingOAuth2UserService(userServices);
		}
		return this.userService;
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
}
