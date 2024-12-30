/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.GenericApplicationListenerAdapter;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.core.ResolvableType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionIdChangedEvent;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Login, which leverages the OAuth 2.0
 * Authorization Code Grant Flow.
 *
 * <p>
 * OAuth 2.0 Login provides an application with the capability to have users log in by
 * using their existing account at an OAuth 2.0 or OpenID Connect 1.0 Provider.
 *
 * <p>
 * Defaults are provided for all configuration options with the only required
 * configuration being
 * {@link #clientRegistrationRepository(ClientRegistrationRepository)}. Alternatively, a
 * {@link ClientRegistrationRepository} {@code @Bean} may be registered instead.
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter}'s are populated:
 *
 * <ul>
 * <li>{@link OAuth2AuthorizationRequestRedirectFilter}</li>
 * <li>{@link OAuth2LoginAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository} (required)</li>
 * <li>{@link OAuth2AuthorizedClientRepository} (optional)</li>
 * <li>{@link GrantedAuthoritiesMapper} (optional)</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository}</li>
 * <li>{@link OAuth2AuthorizedClientRepository}</li>
 * <li>{@link GrantedAuthoritiesMapper}</li>
 * <li>{@link DefaultLoginPageGeneratingFilter} - if {@link #loginPage(String)} is not
 * configured and {@code DefaultLoginPageGeneratingFilter} is available, then a default
 * login page will be made available</li>
 * <li>{@link OidcSessionRegistry}</li>
 * </ul>
 *
 * @author Joe Grandja
 * @author Kazuki Shimizu
 * @author Ngoc Nhan
 * @since 5.0
 * @see HttpSecurity#oauth2Login()
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see OAuth2LoginAuthenticationFilter
 * @see ClientRegistrationRepository
 * @see OAuth2AuthorizedClientRepository
 * @see AbstractAuthenticationFilterConfigurer
 */
public final class OAuth2LoginConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractAuthenticationFilterConfigurer<B, OAuth2LoginConfigurer<B>, OAuth2LoginAuthenticationFilter> {

	private final AuthorizationEndpointConfig authorizationEndpointConfig = new AuthorizationEndpointConfig();

	private final TokenEndpointConfig tokenEndpointConfig = new TokenEndpointConfig();

	private final RedirectionEndpointConfig redirectionEndpointConfig = new RedirectionEndpointConfig();

	private final UserInfoEndpointConfig userInfoEndpointConfig = new UserInfoEndpointConfig();

	private String loginPage;

	private String loginProcessingUrl = OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;

	/**
	 * Sets the repository of client registrations.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 */
	public OAuth2LoginConfigurer<B> clientRegistrationRepository(
			ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	/**
	 * Sets the repository for authorized client(s).
	 * @param authorizedClientRepository the authorized client repository
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 * @since 5.1
	 */
	public OAuth2LoginConfigurer<B> authorizedClientRepository(
			OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.getBuilder().setSharedObject(OAuth2AuthorizedClientRepository.class, authorizedClientRepository);
		return this;
	}

	/**
	 * Sets the service for authorized client(s).
	 * @param authorizedClientService the authorized client service
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 */
	public OAuth2LoginConfigurer<B> authorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientRepository(
				new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService));
		return this;
	}

	@Override
	public OAuth2LoginConfigurer<B> loginPage(String loginPage) {
		Assert.hasText(loginPage, "loginPage cannot be empty");
		this.loginPage = loginPage;
		return this;
	}

	@Override
	public OAuth2LoginConfigurer<B> loginProcessingUrl(String loginProcessingUrl) {
		Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be empty");
		this.loginProcessingUrl = loginProcessingUrl;
		return this;
	}

	/**
	 * Sets the registry for managing the OIDC client-provider session link
	 * @param oidcSessionRegistry the {@link OidcSessionRegistry} to use
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 * @since 6.2
	 */
	public OAuth2LoginConfigurer<B> oidcSessionRegistry(OidcSessionRegistry oidcSessionRegistry) {
		Assert.notNull(oidcSessionRegistry, "oidcSessionRegistry cannot be null");
		getBuilder().setSharedObject(OidcSessionRegistry.class, oidcSessionRegistry);
		return this;
	}

	/**
	 * Returns the {@link AuthorizationEndpointConfig} for configuring the Authorization
	 * Server's Authorization Endpoint.
	 * @return the {@link AuthorizationEndpointConfig}
	 * @deprecated For removal in 7.0. Use {@link #authorizationEndpoint(Customizer)}
	 * instead
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public AuthorizationEndpointConfig authorizationEndpoint() {
		return this.authorizationEndpointConfig;
	}

	/**
	 * Configures the Authorization Server's Authorization Endpoint.
	 * @param authorizationEndpointCustomizer the {@link Customizer} to provide more
	 * options for the {@link AuthorizationEndpointConfig}
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 */
	public OAuth2LoginConfigurer<B> authorizationEndpoint(
			Customizer<AuthorizationEndpointConfig> authorizationEndpointCustomizer) {
		authorizationEndpointCustomizer.customize(this.authorizationEndpointConfig);
		return this;
	}

	/**
	 * Returns the {@link TokenEndpointConfig} for configuring the Authorization Server's
	 * Token Endpoint.
	 * @return the {@link TokenEndpointConfig}
	 * @deprecated For removal in 7.0. Use {@link #tokenEndpoint(Customizer)} or
	 * {@code tokenEndpoint(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public TokenEndpointConfig tokenEndpoint() {
		return this.tokenEndpointConfig;
	}

	/**
	 * Configures the Authorization Server's Token Endpoint.
	 * @param tokenEndpointCustomizer the {@link Customizer} to provide more options for
	 * the {@link TokenEndpointConfig}
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 * @throws Exception
	 */
	public OAuth2LoginConfigurer<B> tokenEndpoint(Customizer<TokenEndpointConfig> tokenEndpointCustomizer) {
		tokenEndpointCustomizer.customize(this.tokenEndpointConfig);
		return this;
	}

	/**
	 * Returns the {@link RedirectionEndpointConfig} for configuring the Client's
	 * Redirection Endpoint.
	 * @return the {@link RedirectionEndpointConfig}
	 * @deprecated For removal in 7.0. Use {@link #redirectionEndpoint(Customizer)}
	 * instead
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public RedirectionEndpointConfig redirectionEndpoint() {
		return this.redirectionEndpointConfig;
	}

	/**
	 * Configures the Client's Redirection Endpoint.
	 * @param redirectionEndpointCustomizer the {@link Customizer} to provide more options
	 * for the {@link RedirectionEndpointConfig}
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 */
	public OAuth2LoginConfigurer<B> redirectionEndpoint(
			Customizer<RedirectionEndpointConfig> redirectionEndpointCustomizer) {
		redirectionEndpointCustomizer.customize(this.redirectionEndpointConfig);
		return this;
	}

	/**
	 * Returns the {@link UserInfoEndpointConfig} for configuring the Authorization
	 * Server's UserInfo Endpoint.
	 * @return the {@link UserInfoEndpointConfig}
	 * @deprecated For removal in 7.0. Use {@link #userInfoEndpoint(Customizer)} or
	 * {@code userInfoEndpoint(Customizer.withDefaults())} to stick with defaults. See the
	 * <a href=
	 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
	 * for more details.
	 */
	@Deprecated(since = "6.1", forRemoval = true)
	public UserInfoEndpointConfig userInfoEndpoint() {
		return this.userInfoEndpointConfig;
	}

	/**
	 * Configures the Authorization Server's UserInfo Endpoint.
	 * @param userInfoEndpointCustomizer the {@link Customizer} to provide more options
	 * for the {@link UserInfoEndpointConfig}
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 */
	public OAuth2LoginConfigurer<B> userInfoEndpoint(Customizer<UserInfoEndpointConfig> userInfoEndpointCustomizer) {
		userInfoEndpointCustomizer.customize(this.userInfoEndpointConfig);
		return this;
	}

	@Override
	public void init(B http) throws Exception {
		OAuth2LoginAuthenticationFilter authenticationFilter = new OAuth2LoginAuthenticationFilter(
				OAuth2ClientConfigurerUtils.getClientRegistrationRepository(this.getBuilder()),
				OAuth2ClientConfigurerUtils.getAuthorizedClientRepository(this.getBuilder()), this.loginProcessingUrl);
		authenticationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		this.setAuthenticationFilter(authenticationFilter);
		super.loginProcessingUrl(this.loginProcessingUrl);
		if (this.loginPage != null) {
			// Set custom login page
			super.loginPage(this.loginPage);
			super.init(http);
		}
		else {
			Map<String, String> loginUrlToClientName = this.getLoginLinks();
			if (loginUrlToClientName.size() == 1) {
				// Setup auto-redirect to provider login page
				// when only 1 client is configured
				this.updateAuthenticationDefaults();
				this.updateAccessDefaults(http);
				String providerLoginPage = loginUrlToClientName.keySet().iterator().next();
				this.registerAuthenticationEntryPoint(http, this.getLoginEntryPoint(http, providerLoginPage));
			}
			else {
				super.init(http);
			}
		}
		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = getAccessTokenResponseClient();
		OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = getOAuth2UserService();
		OAuth2LoginAuthenticationProvider oauth2LoginAuthenticationProvider = new OAuth2LoginAuthenticationProvider(
				accessTokenResponseClient, oauth2UserService);
		GrantedAuthoritiesMapper userAuthoritiesMapper = this.getGrantedAuthoritiesMapper();
		if (userAuthoritiesMapper != null) {
			oauth2LoginAuthenticationProvider.setAuthoritiesMapper(userAuthoritiesMapper);
		}
		http.authenticationProvider(this.postProcess(oauth2LoginAuthenticationProvider));
		boolean oidcAuthenticationProviderEnabled = ClassUtils
			.isPresent("org.springframework.security.oauth2.jwt.JwtDecoder", this.getClass().getClassLoader());
		if (oidcAuthenticationProviderEnabled) {
			OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService = getOidcUserService();
			OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider = new OidcAuthorizationCodeAuthenticationProvider(
					accessTokenResponseClient, oidcUserService);
			JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = this.getJwtDecoderFactoryBean();
			if (jwtDecoderFactory != null) {
				oidcAuthorizationCodeAuthenticationProvider.setJwtDecoderFactory(jwtDecoderFactory);
			}
			if (userAuthoritiesMapper != null) {
				oidcAuthorizationCodeAuthenticationProvider.setAuthoritiesMapper(userAuthoritiesMapper);
			}
			http.authenticationProvider(this.postProcess(oidcAuthorizationCodeAuthenticationProvider));
		}
		else {
			http.authenticationProvider(new OidcAuthenticationRequestChecker());
		}
		this.initDefaultLoginFilter(http);
	}

	@Override
	public void configure(B http) throws Exception {
		OAuth2AuthorizationRequestRedirectFilter authorizationRequestFilter;
		if (this.authorizationEndpointConfig.authorizationRequestResolver != null) {
			authorizationRequestFilter = new OAuth2AuthorizationRequestRedirectFilter(
					this.authorizationEndpointConfig.authorizationRequestResolver);
		}
		else {
			String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
			if (authorizationRequestBaseUri == null) {
				authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
			}
			authorizationRequestFilter = new OAuth2AuthorizationRequestRedirectFilter(
					OAuth2ClientConfigurerUtils.getClientRegistrationRepository(this.getBuilder()),
					authorizationRequestBaseUri);
		}
		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			authorizationRequestFilter
				.setAuthorizationRequestRepository(this.authorizationEndpointConfig.authorizationRequestRepository);
		}
		if (this.authorizationEndpointConfig.authorizationRedirectStrategy != null) {
			authorizationRequestFilter
				.setAuthorizationRedirectStrategy(this.authorizationEndpointConfig.authorizationRedirectStrategy);
		}
		RequestCache requestCache = http.getSharedObject(RequestCache.class);
		if (requestCache != null) {
			authorizationRequestFilter.setRequestCache(requestCache);
		}
		http.addFilter(this.postProcess(authorizationRequestFilter));
		OAuth2LoginAuthenticationFilter authenticationFilter = this.getAuthenticationFilter();
		if (this.redirectionEndpointConfig.authorizationResponseBaseUri != null) {
			authenticationFilter.setFilterProcessesUrl(this.redirectionEndpointConfig.authorizationResponseBaseUri);
		}
		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			authenticationFilter
				.setAuthorizationRequestRepository(this.authorizationEndpointConfig.authorizationRequestRepository);
		}
		configureOidcSessionRegistry(http);
		super.configure(http);
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl);
	}

	@SuppressWarnings("unchecked")
	private JwtDecoderFactory<ClientRegistration> getJwtDecoderFactoryBean() {
		ResolvableType type = ResolvableType.forClassWithGenerics(JwtDecoderFactory.class, ClientRegistration.class);
		String[] names = this.getBuilder().getSharedObject(ApplicationContext.class).getBeanNamesForType(type);
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		return (JwtDecoderFactory<ClientRegistration>) this.getBuilder()
			.getSharedObject(ApplicationContext.class)
			.getBeanProvider(type)
			.getIfUnique();
	}

	private GrantedAuthoritiesMapper getGrantedAuthoritiesMapper() {
		GrantedAuthoritiesMapper grantedAuthoritiesMapper = this.getBuilder()
			.getSharedObject(GrantedAuthoritiesMapper.class);
		if (grantedAuthoritiesMapper == null) {
			grantedAuthoritiesMapper = this.getGrantedAuthoritiesMapperBean();
			if (grantedAuthoritiesMapper != null) {
				this.getBuilder().setSharedObject(GrantedAuthoritiesMapper.class, grantedAuthoritiesMapper);
			}
		}
		return grantedAuthoritiesMapper;
	}

	private GrantedAuthoritiesMapper getGrantedAuthoritiesMapperBean() {
		Map<String, GrantedAuthoritiesMapper> grantedAuthoritiesMapperMap = BeanFactoryUtils
			.beansOfTypeIncludingAncestors(this.getBuilder().getSharedObject(ApplicationContext.class),
					GrantedAuthoritiesMapper.class);
		return (!grantedAuthoritiesMapperMap.isEmpty() ? grantedAuthoritiesMapperMap.values().iterator().next() : null);
	}

	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> getAccessTokenResponseClient() {
		if (this.tokenEndpointConfig.accessTokenResponseClient != null) {
			return this.tokenEndpointConfig.accessTokenResponseClient;
		}
		ResolvableType resolvableType = ResolvableType.forClassWithGenerics(OAuth2AccessTokenResponseClient.class,
				OAuth2AuthorizationCodeGrantRequest.class);
		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> bean = getBeanOrNull(resolvableType);
		return (bean != null) ? bean : new DefaultAuthorizationCodeTokenResponseClient();
	}

	private OAuth2UserService<OidcUserRequest, OidcUser> getOidcUserService() {
		if (this.userInfoEndpointConfig.oidcUserService != null) {
			return this.userInfoEndpointConfig.oidcUserService;
		}
		ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2UserService.class, OidcUserRequest.class,
				OidcUser.class);
		OAuth2UserService<OidcUserRequest, OidcUser> bean = getBeanOrNull(type);
		return (bean != null) ? bean : new OidcUserService();
	}

	private OAuth2UserService<OAuth2UserRequest, OAuth2User> getOAuth2UserService() {
		if (this.userInfoEndpointConfig.userService != null) {
			return this.userInfoEndpointConfig.userService;
		}
		ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2UserService.class, OAuth2UserRequest.class,
				OAuth2User.class);
		OAuth2UserService<OAuth2UserRequest, OAuth2User> bean = getBeanOrNull(type);
		return (bean != null) ? bean : new DefaultOAuth2UserService();
	}

	@SuppressWarnings("unchecked")
	private <T> T getBeanOrNull(ResolvableType type) {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		if (context == null) {
			return null;
		}
		return (T) context.getBeanProvider(type).getIfUnique();
	}

	private void initDefaultLoginFilter(B http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
			.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter == null || this.isCustomLoginPage()) {
			return;
		}
		loginPageGeneratingFilter.setOauth2LoginEnabled(true);
		loginPageGeneratingFilter.setOauth2AuthenticationUrlToClientName(this.getLoginLinks());
		loginPageGeneratingFilter.setLoginPageUrl(this.getLoginPage());
		loginPageGeneratingFilter.setFailureUrl(this.getFailureUrl());
	}

	@SuppressWarnings("unchecked")
	private Map<String, String> getLoginLinks() {
		Iterable<ClientRegistration> clientRegistrations = null;
		ClientRegistrationRepository clientRegistrationRepository = OAuth2ClientConfigurerUtils
			.getClientRegistrationRepository(this.getBuilder());
		ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
		if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
			clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
		}
		if (clientRegistrations == null) {
			return Collections.emptyMap();
		}
		String authorizationRequestBaseUri = (this.authorizationEndpointConfig.authorizationRequestBaseUri != null)
				? this.authorizationEndpointConfig.authorizationRequestBaseUri
				: OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
		Map<String, String> loginUrlToClientName = new HashMap<>();
		clientRegistrations.forEach((registration) -> {
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())) {
				String authorizationRequestUri = authorizationRequestBaseUri + "/" + registration.getRegistrationId();
				loginUrlToClientName.put(authorizationRequestUri, registration.getClientName());
			}
		});
		return loginUrlToClientName;
	}

	private AuthenticationEntryPoint getLoginEntryPoint(B http, String providerLoginPage) {
		RequestMatcher loginPageMatcher = new AntPathRequestMatcher(this.getLoginPage());
		RequestMatcher faviconMatcher = new AntPathRequestMatcher("/favicon.ico");
		RequestMatcher defaultEntryPointMatcher = this.getAuthenticationEntryPointMatcher(http);
		RequestMatcher defaultLoginPageMatcher = new AndRequestMatcher(
				new OrRequestMatcher(loginPageMatcher, faviconMatcher), defaultEntryPointMatcher);
		RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
				new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));
		RequestMatcher formLoginNotEnabled = getFormLoginNotEnabledRequestMatcher(http);
		LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
		entryPoints.put(new AndRequestMatcher(notXRequestedWith, new NegatedRequestMatcher(defaultLoginPageMatcher),
				formLoginNotEnabled), new LoginUrlAuthenticationEntryPoint(providerLoginPage));
		DelegatingAuthenticationEntryPoint loginEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
		loginEntryPoint.setDefaultEntryPoint(this.getAuthenticationEntryPoint());
		return loginEntryPoint;
	}

	private RequestMatcher getFormLoginNotEnabledRequestMatcher(B http) {
		DefaultLoginPageGeneratingFilter defaultLoginPageGeneratingFilter = http
			.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		Field formLoginEnabledField = (defaultLoginPageGeneratingFilter != null)
				? ReflectionUtils.findField(DefaultLoginPageGeneratingFilter.class, "formLoginEnabled") : null;
		if (formLoginEnabledField != null) {
			ReflectionUtils.makeAccessible(formLoginEnabledField);
			return (request) -> Boolean.FALSE
				.equals(ReflectionUtils.getField(formLoginEnabledField, defaultLoginPageGeneratingFilter));
		}
		return AnyRequestMatcher.INSTANCE;
	}

	private void configureOidcSessionRegistry(B http) {
		if (http.getConfigurer(OidcLogoutConfigurer.class) == null
				&& http.getSharedObject(OidcSessionRegistry.class) == null) {
			return;
		}
		OidcSessionRegistry sessionRegistry = OAuth2ClientConfigurerUtils.getOidcSessionRegistry(http);
		SessionManagementConfigurer<B> sessionConfigurer = http.getConfigurer(SessionManagementConfigurer.class);
		if (sessionConfigurer != null) {
			OidcSessionRegistryAuthenticationStrategy sessionAuthenticationStrategy = new OidcSessionRegistryAuthenticationStrategy();
			sessionAuthenticationStrategy.setSessionRegistry(sessionRegistry);
			sessionConfigurer.addSessionAuthenticationStrategy(sessionAuthenticationStrategy);
		}
		OidcClientSessionEventListener listener = new OidcClientSessionEventListener();
		listener.setSessionRegistry(sessionRegistry);
		registerDelegateApplicationListener(listener);
	}

	private void registerDelegateApplicationListener(ApplicationListener<?> delegate) {
		DelegatingApplicationListener delegating = getBeanOrNull(
				ResolvableType.forType(DelegatingApplicationListener.class));
		if (delegating == null) {
			return;
		}
		SmartApplicationListener smartListener = new GenericApplicationListenerAdapter(delegate);
		delegating.addListener(smartListener);
	}

	/**
	 * Configuration options for the Authorization Server's Authorization Endpoint.
	 */
	public final class AuthorizationEndpointConfig {

		private String authorizationRequestBaseUri;

		private OAuth2AuthorizationRequestResolver authorizationRequestResolver;

		private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

		private RedirectStrategy authorizationRedirectStrategy;

		private AuthorizationEndpointConfig() {
		}

		/**
		 * Sets the base {@code URI} used for authorization requests.
		 * @param authorizationRequestBaseUri the base {@code URI} used for authorization
		 * requests
		 * @return the {@link AuthorizationEndpointConfig} for further configuration
		 */
		public AuthorizationEndpointConfig baseUri(String authorizationRequestBaseUri) {
			Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
			this.authorizationRequestBaseUri = authorizationRequestBaseUri;
			return this;
		}

		/**
		 * Sets the resolver used for resolving {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestResolver the resolver used for resolving
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link AuthorizationEndpointConfig} for further configuration
		 * @since 5.1
		 */
		public AuthorizationEndpointConfig authorizationRequestResolver(
				OAuth2AuthorizationRequestResolver authorizationRequestResolver) {
			Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
			this.authorizationRequestResolver = authorizationRequestResolver;
			return this;
		}

		/**
		 * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestRepository the repository used for storing
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link AuthorizationEndpointConfig} for further configuration
		 */
		public AuthorizationEndpointConfig authorizationRequestRepository(
				AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
			Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
			this.authorizationRequestRepository = authorizationRequestRepository;
			return this;
		}

		/**
		 * Sets the redirect strategy for Authorization Endpoint redirect URI.
		 * @param authorizationRedirectStrategy the redirect strategy
		 * @return the {@link AuthorizationEndpointConfig} for further configuration
		 */
		public AuthorizationEndpointConfig authorizationRedirectStrategy(
				RedirectStrategy authorizationRedirectStrategy) {
			this.authorizationRedirectStrategy = authorizationRedirectStrategy;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 * @return the {@link OAuth2LoginConfigurer}
		 * @deprecated For removal in 7.0. Use {@link #authorizationEndpoint(Customizer)}
		 * instead
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}

	}

	/**
	 * Configuration options for the Authorization Server's Token Endpoint.
	 */
	public final class TokenEndpointConfig {

		private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

		private TokenEndpointConfig() {
		}

		/**
		 * Sets the client used for requesting the access token credential from the Token
		 * Endpoint.
		 * @param accessTokenResponseClient the client used for requesting the access
		 * token credential from the Token Endpoint
		 * @return the {@link TokenEndpointConfig} for further configuration
		 */
		public TokenEndpointConfig accessTokenResponseClient(
				OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {
			Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
			this.accessTokenResponseClient = accessTokenResponseClient;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 * @return the {@link OAuth2LoginConfigurer}
		 * @deprecated For removal in 7.0. Use {@link #tokenEndpoint(Customizer)} or
		 * {@code tokenEndpoint(Customizer.withDefaults())} to stick with defaults. See
		 * the <a href=
		 * "https://docs.spring.io/spring-security/reference/migration-7/configuration.html#_use_the_lambda_dsl">documentation</a>
		 * for more details.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}

	}

	/**
	 * Configuration options for the Client's Redirection Endpoint.
	 */
	public final class RedirectionEndpointConfig {

		private String authorizationResponseBaseUri;

		private RedirectionEndpointConfig() {
		}

		/**
		 * Sets the {@code URI} where the authorization response will be processed.
		 * @param authorizationResponseBaseUri the {@code URI} where the authorization
		 * response will be processed
		 * @return the {@link RedirectionEndpointConfig} for further configuration
		 */
		public RedirectionEndpointConfig baseUri(String authorizationResponseBaseUri) {
			Assert.hasText(authorizationResponseBaseUri, "authorizationResponseBaseUri cannot be empty");
			this.authorizationResponseBaseUri = authorizationResponseBaseUri;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 * @return the {@link OAuth2LoginConfigurer}
		 * @deprecated For removal in 7.0. Use {@link #redirectionEndpoint(Customizer)}
		 * instead
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}

	}

	/**
	 * Configuration options for the Authorization Server's UserInfo Endpoint.
	 */
	public final class UserInfoEndpointConfig {

		private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;

		private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;

		private UserInfoEndpointConfig() {
		}

		/**
		 * Sets the OAuth 2.0 service used for obtaining the user attributes of the
		 * End-User from the UserInfo Endpoint.
		 * @param userService the OAuth 2.0 service used for obtaining the user attributes
		 * of the End-User from the UserInfo Endpoint
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig userService(OAuth2UserService<OAuth2UserRequest, OAuth2User> userService) {
			Assert.notNull(userService, "userService cannot be null");
			this.userService = userService;
			return this;
		}

		/**
		 * Sets the OpenID Connect 1.0 service used for obtaining the user attributes of
		 * the End-User from the UserInfo Endpoint.
		 * @param oidcUserService the OpenID Connect 1.0 service used for obtaining the
		 * user attributes of the End-User from the UserInfo Endpoint
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig oidcUserService(OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService) {
			Assert.notNull(oidcUserService, "oidcUserService cannot be null");
			this.oidcUserService = oidcUserService;
			return this;
		}

		/**
		 * Sets the {@link GrantedAuthoritiesMapper} used for mapping
		 * {@link OAuth2User#getAuthorities()}.
		 * @param userAuthoritiesMapper the {@link GrantedAuthoritiesMapper} used for
		 * mapping the user's authorities
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper) {
			Assert.notNull(userAuthoritiesMapper, "userAuthoritiesMapper cannot be null");
			OAuth2LoginConfigurer.this.getBuilder()
				.setSharedObject(GrantedAuthoritiesMapper.class, userAuthoritiesMapper);
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 * @return the {@link OAuth2LoginConfigurer}
		 * @deprecated For removal in 7.0. Use {@link #userInfoEndpoint(Customizer)}
		 * instead
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}

	}

	private static class OidcAuthenticationRequestChecker implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			OAuth2LoginAuthenticationToken authorizationCodeAuthentication = (OAuth2LoginAuthenticationToken) authentication;
			OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationExchange()
				.getAuthorizationRequest();
			if (authorizationRequest.getScopes().contains(OidcScopes.OPENID)) {
				// Section 3.1.2.1 Authentication Request -
				// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest scope
				// REQUIRED. OpenID Connect requests MUST contain the "openid" scope
				// value.
				OAuth2Error oauth2Error = new OAuth2Error("oidc_provider_not_configured",
						"An OpenID Connect Authentication Provider has not been configured. "
								+ "Check to ensure you include the dependency 'spring-security-oauth2-jose'.",
						null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			return null;
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication);
		}

	}

	private static final class OidcClientSessionEventListener implements ApplicationListener<AbstractSessionEvent> {

		private final Log logger = LogFactory.getLog(OidcClientSessionEventListener.class);

		private OidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();

		/**
		 * {@inheritDoc}
		 */
		@Override
		public void onApplicationEvent(AbstractSessionEvent event) {
			if (event instanceof SessionDestroyedEvent destroyed) {
				this.logger.debug("Received SessionDestroyedEvent");
				this.sessionRegistry.removeSessionInformation(destroyed.getId());
				return;
			}
			if (event instanceof SessionIdChangedEvent changed) {
				this.logger.debug("Received SessionIdChangedEvent");
				OidcSessionInformation information = this.sessionRegistry
					.removeSessionInformation(changed.getOldSessionId());
				if (information == null) {
					this.logger
						.debug("Failed to register new session id since old session id was not found in registry");
					return;
				}
				this.sessionRegistry.saveSessionInformation(information.withSessionId(changed.getNewSessionId()));
			}
		}

		/**
		 * The registry where OIDC Provider sessions are linked to the Client session.
		 * Defaults to in-memory storage.
		 * @param sessionRegistry the {@link OidcSessionRegistry} to use
		 */
		void setSessionRegistry(OidcSessionRegistry sessionRegistry) {
			Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
			this.sessionRegistry = sessionRegistry;
		}

	}

	private static final class OidcSessionRegistryAuthenticationStrategy implements SessionAuthenticationStrategy {

		private final Log logger = LogFactory.getLog(getClass());

		private OidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();

		/**
		 * {@inheritDoc}
		 */
		@Override
		public void onAuthentication(Authentication authentication, HttpServletRequest request,
				HttpServletResponse response) throws SessionAuthenticationException {
			HttpSession session = request.getSession(false);
			if (session == null) {
				return;
			}
			if (!(authentication.getPrincipal() instanceof OidcUser user)) {
				return;
			}
			String sessionId = session.getId();
			CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
			Map<String, String> headers = (csrfToken != null) ? Map.of(csrfToken.getHeaderName(), csrfToken.getToken())
					: Collections.emptyMap();
			OidcSessionInformation registration = new OidcSessionInformation(sessionId, headers, user);
			if (this.logger.isTraceEnabled()) {
				this.logger
					.trace(String.format("Linking a provider [%s] session to this client's session", user.getIssuer()));
			}
			this.sessionRegistry.saveSessionInformation(registration);
		}

		/**
		 * The registration for linking OIDC Provider Session information to the Client's
		 * session. Defaults to in-memory storage.
		 * @param sessionRegistry the {@link OidcSessionRegistry} to use
		 */
		void setSessionRegistry(OidcSessionRegistry sessionRegistry) {
			Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
			this.sessionRegistry = sessionRegistry;
		}

	}

}
