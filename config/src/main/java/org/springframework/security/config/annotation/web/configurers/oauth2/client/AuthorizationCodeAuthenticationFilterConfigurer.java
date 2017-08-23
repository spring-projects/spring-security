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
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.jose.jws.JwsAlgorithm;
import org.springframework.security.jwt.JwtDecoder;
import org.springframework.security.jwt.nimbus.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.jwt.DefaultProviderJwtDecoderRegistry;
import org.springframework.security.oauth2.client.authentication.jwt.ProviderJwtDecoderRegistry;
import org.springframework.security.oauth2.client.authentication.nimbus.NimbusAuthorizationCodeTokenExchanger;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.token.InMemoryAccessTokenRepository;
import org.springframework.security.oauth2.client.token.SecurityTokenRepository;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.client.user.nimbus.NimbusOAuth2UserService;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.http.HttpClientConfig;
import org.springframework.security.oauth2.core.provider.DefaultProviderMetadata;
import org.springframework.security.oauth2.core.provider.ProviderMetadata;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestVariablesExtractor;
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
final class AuthorizationCodeAuthenticationFilterConfigurer<H extends HttpSecurityBuilder<H>, R extends RequestMatcher & RequestVariablesExtractor> extends
		AbstractAuthenticationFilterConfigurer<H, AuthorizationCodeAuthenticationFilterConfigurer<H, R>, AuthorizationCodeAuthenticationProcessingFilter> {

	private R authorizationResponseMatcher;
	private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger;
	private SecurityTokenRepository<AccessToken> accessTokenRepository;
	private OAuth2UserService userInfoService;
	private Map<URI, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();
	private Map<URI, String> userNameAttributeNames = new HashMap<>();
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

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> userNameAttributeName(String userNameAttributeName, URI userInfoUri) {
		Assert.hasText(userNameAttributeName, "userNameAttributeName cannot be empty");
		Assert.notNull(userInfoUri, "userInfoUri cannot be null");
		this.userNameAttributeNames.put(userInfoUri, userNameAttributeName);
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper) {
		Assert.notNull(userAuthoritiesMapper, "userAuthoritiesMapper cannot be null");
		this.userAuthoritiesMapper = userAuthoritiesMapper;
		return this;
	}

	AuthorizationCodeAuthenticationFilterConfigurer<H, R> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notEmpty(clientRegistrationRepository.getRegistrations(), "clientRegistrationRepository cannot be empty");
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
			this.getAuthorizationCodeTokenExchanger(http), this.getAccessTokenRepository(),
			this.getProviderJwtDecoderRegistry(http), this.getUserInfoService(http));
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

	private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> getAuthorizationCodeTokenExchanger(H http) {
		if (this.authorizationCodeTokenExchanger == null) {
			NimbusAuthorizationCodeTokenExchanger nimbusAuthorizationCodeTokenExchanger = new NimbusAuthorizationCodeTokenExchanger();
			HttpClientConfig httpClientConfig = this.getHttpClientConfig(http);
			if (httpClientConfig != null) {
				nimbusAuthorizationCodeTokenExchanger.setHttpClientConfig(httpClientConfig);
			}
			this.authorizationCodeTokenExchanger = nimbusAuthorizationCodeTokenExchanger;
		}
		return this.authorizationCodeTokenExchanger;
	}

	private SecurityTokenRepository<AccessToken> getAccessTokenRepository() {
		if (this.accessTokenRepository == null) {
			this.accessTokenRepository = new InMemoryAccessTokenRepository();
		}
		return this.accessTokenRepository;
	}

	private ProviderJwtDecoderRegistry getProviderJwtDecoderRegistry(H http) {
		HttpClientConfig httpClientConfig = this.getHttpClientConfig(http);
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
				NimbusJwtDecoderJwkSupport nimbusJwtDecoderJwkSupport = new NimbusJwtDecoderJwkSupport(
					providerDetails.getJwkSetUri(), JwsAlgorithm.RS256, httpClientConfig);
				jwtDecoders.put(providerMetadata, nimbusJwtDecoderJwkSupport);
			}
		});
		return new DefaultProviderJwtDecoderRegistry(jwtDecoders);
	}

	private OAuth2UserService getUserInfoService(H http) {
		if (this.userInfoService == null) {
			NimbusOAuth2UserService nimbusOAuth2UserService = new NimbusOAuth2UserService();
			if (!this.customUserTypes.isEmpty()) {
				nimbusOAuth2UserService.setCustomUserTypes(this.customUserTypes);
			}
			if (!this.userNameAttributeNames.isEmpty()) {
				nimbusOAuth2UserService.setUserNameAttributeNames(this.userNameAttributeNames);
			}
			HttpClientConfig httpClientConfig = this.getHttpClientConfig(http);
			if (httpClientConfig != null) {
				nimbusOAuth2UserService.setHttpClientConfig(httpClientConfig);
			}
			this.userInfoService = nimbusOAuth2UserService;
		}
		return this.userInfoService;
	}

	private HttpClientConfig getHttpClientConfig(H http) {
		Map<String, HttpClientConfig> httpClientConfigs =
			http.getSharedObject(ApplicationContext.class).getBeansOfType(HttpClientConfig.class);
		return (!httpClientConfigs.isEmpty() ? httpClientConfigs.values().iterator().next() : null);
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
