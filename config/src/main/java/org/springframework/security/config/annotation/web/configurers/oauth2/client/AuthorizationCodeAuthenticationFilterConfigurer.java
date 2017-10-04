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

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticator;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantAuthenticator;
import org.springframework.security.oauth2.client.authentication.DelegatingAuthorizationGrantAuthenticator;
import org.springframework.security.oauth2.client.authentication.jwt.JwtDecoderRegistry;
import org.springframework.security.oauth2.client.authentication.jwt.nimbus.NimbusJwtDecoderRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.token.InMemoryAccessTokenRepository;
import org.springframework.security.oauth2.client.token.SecurityTokenRepository;
import org.springframework.security.oauth2.client.user.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.user.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.user.DelegatingOAuth2UserService;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationCodeAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.web.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.web.nimbus.NimbusAuthorizationCodeTokenExchanger;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.client.authentication.OidcAuthorizationCodeAuthenticator;
import org.springframework.security.oauth2.oidc.client.user.OidcUserService;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Joe Grandja
 */
final class AuthorizationCodeAuthenticationFilterConfigurer<H extends HttpSecurityBuilder<H>, R extends RequestMatcher> extends
		AbstractAuthenticationFilterConfigurer<H, AuthorizationCodeAuthenticationFilterConfigurer<H, R>, AuthorizationCodeAuthenticationProcessingFilter> {

	private R authorizationResponseMatcher;
	private AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken> authorizationCodeAuthenticator;
	private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger;
	private SecurityTokenRepository<AccessToken> accessTokenRepository;
	private JwtDecoderRegistry jwtDecoderRegistry;
	private OAuth2UserService userInfoService;
	private Map<URI, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();
	private GrantedAuthoritiesMapper userAuthoritiesMapper;

	AuthorizationCodeAuthenticationFilterConfigurer() {
		super(new AuthorizationCodeAuthenticationProcessingFilter(), null);
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> authorizationResponseMatcher(R authorizationResponseMatcher) {
		Assert.notNull(authorizationResponseMatcher, "authorizationResponseMatcher cannot be null");
		this.authorizationResponseMatcher = authorizationResponseMatcher;
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> authorizationCodeTokenExchanger(
			AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger) {

		Assert.notNull(authorizationCodeTokenExchanger, "authorizationCodeTokenExchanger cannot be null");
		this.authorizationCodeTokenExchanger = authorizationCodeTokenExchanger;
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> accessTokenRepository(SecurityTokenRepository<AccessToken> accessTokenRepository) {
		Assert.notNull(accessTokenRepository, "accessTokenRepository cannot be null");
		this.accessTokenRepository = accessTokenRepository;
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> jwtDecoderRegistry(JwtDecoderRegistry jwtDecoderRegistry) {
		Assert.notNull(jwtDecoderRegistry, "jwtDecoderRegistry cannot be null");
		this.jwtDecoderRegistry = jwtDecoderRegistry;
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> userInfoService(OAuth2UserService userInfoService) {
		Assert.notNull(userInfoService, "userInfoService cannot be null");
		this.userInfoService = userInfoService;
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> customUserType(Class<? extends OAuth2User> customUserType, URI userInfoUri) {
		Assert.notNull(customUserType, "customUserType cannot be null");
		Assert.notNull(userInfoUri, "userInfoUri cannot be null");
		this.customUserTypes.put(userInfoUri, customUserType);
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper) {
		Assert.notNull(userAuthoritiesMapper, "userAuthoritiesMapper cannot be null");
		this.userAuthoritiesMapper = userAuthoritiesMapper;
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	String getLoginUrl() {
		return super.getLoginPage();
	}

	String getLoginFailureUrl() {
		return super.getFailureUrl();
	}

	@Override
	public void init(H http) throws Exception {
		AuthorizationCodeAuthenticationProvider authenticationProvider = new AuthorizationCodeAuthenticationProvider(
			this.getAuthorizationCodeAuthenticator(), this.getAccessTokenRepository(), this.getUserInfoService());
		if (this.userAuthoritiesMapper != null) {
			authenticationProvider.setAuthoritiesMapper(this.userAuthoritiesMapper);
		}
		authenticationProvider = this.postProcess(authenticationProvider);
		http.authenticationProvider(authenticationProvider);
		super.init(http);
	}

	@Override
	public void configure(H http) throws Exception {
		AuthorizationCodeAuthenticationProcessingFilter authFilter = this.getAuthenticationFilter();
		if (this.authorizationResponseMatcher != null) {
			authFilter.setAuthorizationResponseMatcher(this.authorizationResponseMatcher);
		}
		authFilter.setClientRegistrationRepository(OAuth2LoginConfigurer.getClientRegistrationRepository(this.getBuilder()));
		super.configure(http);
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return (this.authorizationResponseMatcher != null ?
			this.authorizationResponseMatcher : this.getAuthenticationFilter().getAuthorizationResponseMatcher());
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

	private SecurityTokenRepository<AccessToken> getAccessTokenRepository() {
		if (this.accessTokenRepository == null) {
			this.accessTokenRepository = new InMemoryAccessTokenRepository();
		}
		return this.accessTokenRepository;
	}

	private JwtDecoderRegistry getJwtDecoderRegistry() {
		if (this.jwtDecoderRegistry == null) {
			this.jwtDecoderRegistry = new NimbusJwtDecoderRegistry();
		}
		return this.jwtDecoderRegistry;
	}

	private OAuth2UserService getUserInfoService() {
		if (this.userInfoService == null) {
			List<OAuth2UserService> oauth2UserServices = new ArrayList<>();
			oauth2UserServices.add(new DefaultOAuth2UserService());
			oauth2UserServices.add(new OidcUserService());
			if (!this.customUserTypes.isEmpty()) {
				oauth2UserServices.add(new CustomUserTypesOAuth2UserService(this.customUserTypes));
			}
			this.userInfoService = new DelegatingOAuth2UserService(oauth2UserServices);
		}
		return this.userInfoService;
	}
}
