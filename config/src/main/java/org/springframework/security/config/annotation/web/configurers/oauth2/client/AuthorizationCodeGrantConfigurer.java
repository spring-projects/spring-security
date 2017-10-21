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
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.NimbusAuthorizationCodeTokenExchanger;
import org.springframework.security.oauth2.client.authentication.jwt.JwtDecoderRegistry;
import org.springframework.security.oauth2.client.authentication.jwt.NimbusJwtDecoderRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.token.SecurityTokenRepository;
import org.springframework.security.oauth2.client.web.AuthorizationCodeAuthenticationFilter;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.oidc.client.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.Assert;

/**
 * A security configurer for the Authorization Code Grant type.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public class AuthorizationCodeGrantConfigurer<B extends HttpSecurityBuilder<B>> extends
	AbstractHttpConfigurer<AuthorizationCodeGrantConfigurer<B>, B> {

	// ***** Authorization Request members
	private AuthorizationRequestRedirectFilter authorizationRequestFilter;
	private String authorizationRequestBaseUri;
	private AuthorizationRequestUriBuilder authorizationRequestUriBuilder;
	private AuthorizationRequestRepository authorizationRequestRepository;

	// ***** Authorization Response members
	private AuthorizationCodeAuthenticationFilter authorizationResponseFilter;
	private String authorizationResponseBaseUri;
	private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger;
	private SecurityTokenRepository<AccessToken> accessTokenRepository;
	private JwtDecoderRegistry jwtDecoderRegistry;

	public AuthorizationCodeGrantConfigurer<B> authorizationRequestBaseUri(String authorizationRequestBaseUri) {
		Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
		this.authorizationRequestBaseUri = authorizationRequestBaseUri;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> authorizationRequestUriBuilder(AuthorizationRequestUriBuilder authorizationRequestUriBuilder) {
		Assert.notNull(authorizationRequestUriBuilder, "authorizationRequestUriBuilder cannot be null");
		this.authorizationRequestUriBuilder = authorizationRequestUriBuilder;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> authorizationRequestRepository(AuthorizationRequestRepository authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
		return this;
	}

	public AuthorizationCodeGrantConfigurer<B> authorizationResponseBaseUri(String authorizationResponseBaseUri) {
		Assert.hasText(authorizationResponseBaseUri, "authorizationResponseBaseUri cannot be empty");
		this.authorizationResponseBaseUri = authorizationResponseBaseUri;
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

	public AuthorizationCodeGrantConfigurer<B> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	@Override
	public final void init(B http) throws Exception {
		AuthorizationCodeAuthenticationProvider oauth2AuthorizationCodeAuthenticationProvider =
			new AuthorizationCodeAuthenticationProvider(this.getAuthorizationCodeTokenExchanger());
		if (this.accessTokenRepository != null) {
			oauth2AuthorizationCodeAuthenticationProvider.setAccessTokenRepository(this.accessTokenRepository);
		}
		http.authenticationProvider(this.postProcess(oauth2AuthorizationCodeAuthenticationProvider));

		OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider =
			new OidcAuthorizationCodeAuthenticationProvider(
				this.getAuthorizationCodeTokenExchanger(), this.getJwtDecoderRegistry());
		if (this.accessTokenRepository != null) {
			oidcAuthorizationCodeAuthenticationProvider.setAccessTokenRepository(this.accessTokenRepository);
		}
		http.authenticationProvider(this.postProcess(oidcAuthorizationCodeAuthenticationProvider));

		this.authorizationRequestFilter = new AuthorizationRequestRedirectFilter(
			this.authorizationRequestBaseUri != null ?
				this.authorizationRequestBaseUri :
				AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI,
			this.getClientRegistrationRepository());
		if (this.authorizationRequestUriBuilder != null) {
			this.authorizationRequestFilter.setAuthorizationRequestUriBuilder(this.authorizationRequestUriBuilder);
		}
		if (this.authorizationRequestRepository != null) {
			this.authorizationRequestFilter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
		}

		this.authorizationResponseFilter = new AuthorizationCodeAuthenticationFilter(
			this.authorizationResponseBaseUri != null ?
				this.authorizationResponseBaseUri :
				AuthorizationCodeAuthenticationFilter.DEFAULT_AUTHORIZATION_RESPONSE_BASE_URI);
		this.authorizationResponseFilter.setClientRegistrationRepository(this.getClientRegistrationRepository());
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

	AuthorizationRequestRedirectFilter getAuthorizationRequestFilter() {
		return this.authorizationRequestFilter;
	}

	String getAuthorizationRequestBaseUri() {
		return this.authorizationRequestBaseUri;
	}

	String getAuthorizationResponseBaseUri() {
		return this.authorizationResponseBaseUri;
	}

	AuthorizationRequestRepository getAuthorizationRequestRepository() {
		return this.authorizationRequestRepository;
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
