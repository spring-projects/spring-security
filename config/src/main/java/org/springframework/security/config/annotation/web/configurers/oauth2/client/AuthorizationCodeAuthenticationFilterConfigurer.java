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
import org.springframework.security.jwt.JwtDecoder;
import org.springframework.security.jwt.nimbus.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.nimbus.NimbusAuthorizationCodeTokenExchanger;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.client.user.nimbus.NimbusOAuth2UserService;
import org.springframework.security.oauth2.client.authentication.jwt.DefaultProviderJwtDecoderRegistry;
import org.springframework.security.oauth2.core.provider.DefaultProviderMetadata;
import org.springframework.security.oauth2.client.authentication.jwt.ProviderJwtDecoderRegistry;
import org.springframework.security.oauth2.core.provider.ProviderMetadata;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Joe Grandja
 */
final class AuthorizationCodeAuthenticationFilterConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractAuthenticationFilterConfigurer<H, AuthorizationCodeAuthenticationFilterConfigurer<H>, AuthorizationCodeAuthenticationProcessingFilter> {

	private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger;
	private OAuth2UserService userInfoService;
	private Map<URI, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();
	private Map<URI, String> userNameAttributeNames = new HashMap<>();


	AuthorizationCodeAuthenticationFilterConfigurer() {
		super(new AuthorizationCodeAuthenticationProcessingFilter(), null);
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notEmpty(clientRegistrationRepository.getRegistrations(), "clientRegistrationRepository cannot be empty");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H> authorizationCodeTokenExchanger(
			AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger) {

		Assert.notNull(authorizationCodeTokenExchanger, "authorizationCodeTokenExchanger cannot be null");
		this.authorizationCodeTokenExchanger = authorizationCodeTokenExchanger;
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H> userInfoService(OAuth2UserService userInfoService) {
		Assert.notNull(userInfoService, "userInfoService cannot be null");
		this.userInfoService = userInfoService;
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H> customUserType(Class<? extends OAuth2User> customUserType, URI userInfoUri) {
		Assert.notNull(customUserType, "customUserType cannot be null");
		Assert.notNull(userInfoUri, "userInfoUri cannot be null");
		this.customUserTypes.put(userInfoUri, customUserType);
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H> userNameAttributeName(String userNameAttributeName, URI userInfoUri) {
		Assert.hasText(userNameAttributeName, "userNameAttributeName cannot be empty");
		Assert.notNull(userInfoUri, "userInfoUri cannot be null");
		this.userNameAttributeNames.put(userInfoUri, userNameAttributeName);
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
				this.getAuthorizationCodeTokenExchanger(), this.getProviderJwtDecoderRegistry(), this.getUserInfoService());
		authenticationProvider = this.postProcess(authenticationProvider);
		http.authenticationProvider(authenticationProvider);
		super.init(http);
	}

	@Override
	public void configure(H http) throws Exception {
		AuthorizationCodeAuthenticationProcessingFilter authFilter = this.getAuthenticationFilter();
		authFilter.setClientRegistrationRepository(OAuth2LoginConfigurer.getClientRegistrationRepository(this.getBuilder()));
		super.configure(http);
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return this.getAuthenticationFilter().getAuthorizeRequestMatcher();
	}

	private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> getAuthorizationCodeTokenExchanger() {
		if (this.authorizationCodeTokenExchanger == null) {
			this.authorizationCodeTokenExchanger = new NimbusAuthorizationCodeTokenExchanger();
		}
		return this.authorizationCodeTokenExchanger;
	}

	private ProviderJwtDecoderRegistry getProviderJwtDecoderRegistry() {
		Map<ProviderMetadata, JwtDecoder> jwtDecoders = new HashMap<>();
		ClientRegistrationRepository clientRegistrationRepository = OAuth2LoginConfigurer.getClientRegistrationRepository(this.getBuilder());
		clientRegistrationRepository.getRegistrations().stream().forEach(registration -> {
			ClientRegistration.ProviderDetails providerDetails = registration.getProviderDetails();
			if (StringUtils.hasText(providerDetails.getJwkSetUri())) {
				DefaultProviderMetadata providerMetadata = new DefaultProviderMetadata();
				// Default the Issuer to the host of the Authorization Endpoint
				providerMetadata.setIssuer(this.toURL(
					UriComponentsBuilder
						.fromHttpUrl(providerDetails.getAuthorizationUri())
						.replacePath(null)
						.toUriString()
				));
				providerMetadata.setAuthorizationEndpoint(this.toURL(providerDetails.getAuthorizationUri()));
				providerMetadata.setTokenEndpoint(this.toURL(providerDetails.getTokenUri()));
				providerMetadata.setUserInfoEndpoint(this.toURL(providerDetails.getUserInfoUri()));
				providerMetadata.setJwkSetUri(this.toURL(providerDetails.getJwkSetUri()));
				jwtDecoders.put(providerMetadata, new NimbusJwtDecoderJwkSupport(providerDetails.getJwkSetUri()));
			}
		});
		return new DefaultProviderJwtDecoderRegistry(jwtDecoders);
	}

	private OAuth2UserService getUserInfoService() {
		if (this.userInfoService == null) {
			this.userInfoService = new NimbusOAuth2UserService();
			if (!this.customUserTypes.isEmpty()) {
				((NimbusOAuth2UserService)this.userInfoService).setCustomUserTypes(this.customUserTypes);
			}
			if (!this.userNameAttributeNames.isEmpty()) {
				((NimbusOAuth2UserService)this.userInfoService).setUserNameAttributeNames(this.userNameAttributeNames);
			}
		}
		return this.userInfoService;
	}

	private URL toURL(String urlStr) {
		if (!StringUtils.hasText(urlStr)) {
			return null;
		}
		try {
			return new URL(urlStr);
		} catch (MalformedURLException ex) {
			throw new IllegalArgumentException("Failed to convert '" + urlStr + "' to a URL: " + ex.getMessage(), ex);
		}
	}
}
