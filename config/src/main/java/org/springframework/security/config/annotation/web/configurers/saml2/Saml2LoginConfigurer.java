/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.saml2;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.opensaml.core.Version;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.DefaultSaml2AuthenticationRequestContextResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AbstractHttpConfigurer} for SAML 2.0 Login, which leverages the SAML 2.0 Web
 * Browser Single Sign On (WebSSO) Flow.
 *
 * <p>
 * SAML 2.0 Login provides an application with the capability to have users log in by
 * using their existing account at an SAML 2.0 Identity Provider.
 *
 * <p>
 * Defaults are provided for all configuration options with the only required
 * configuration being
 * {@link #relyingPartyRegistrationRepository(RelyingPartyRegistrationRepository)} .
 * Alternatively, a {@link RelyingPartyRegistrationRepository} {@code @Bean} may be
 * registered instead.
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter}'s are populated:
 *
 * <ul>
 * <li>{@link Saml2WebSsoAuthenticationFilter}</li>
 * <li>{@link Saml2WebSsoAuthenticationRequestFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated:
 *
 * <ul>
 * <li>{@link RelyingPartyRegistrationRepository} (required)</li>
 * <li>{@link Saml2AuthenticationRequestFactory} (optional)</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link RelyingPartyRegistrationRepository} (required)</li>
 * <li>{@link Saml2AuthenticationRequestFactory} (optional)</li>
 * <li>{@link DefaultLoginPageGeneratingFilter} - if {@link #loginPage(String)} is not
 * configured and {@code DefaultLoginPageGeneratingFilter} is available, than a default
 * login page will be made available</li>
 * </ul>
 *
 * @since 5.2
 * @see HttpSecurity#saml2Login()
 * @see Saml2WebSsoAuthenticationFilter
 * @see Saml2WebSsoAuthenticationRequestFilter
 * @see RelyingPartyRegistrationRepository
 * @see AbstractAuthenticationFilterConfigurer
 */
public final class Saml2LoginConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractAuthenticationFilterConfigurer<B, Saml2LoginConfigurer<B>, Saml2WebSsoAuthenticationFilter> {

	private String loginPage;

	private String loginProcessingUrl = Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;

	private AuthenticationRequestEndpointConfig authenticationRequestEndpoint = new AuthenticationRequestEndpointConfig();

	private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	private AuthenticationConverter authenticationConverter;

	private AuthenticationManager authenticationManager;

	private Saml2WebSsoAuthenticationFilter saml2WebSsoAuthenticationFilter;

	/**
	 * Use this {@link AuthenticationConverter} when converting incoming requests to an
	 * {@link Authentication}. By default the {@link Saml2AuthenticationTokenConverter} is
	 * used.
	 * @param authenticationConverter the {@link AuthenticationConverter} to use
	 * @return the {@link Saml2LoginConfigurer} for further configuration
	 * @since 5.4
	 */
	public Saml2LoginConfigurer<B> authenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
		return this;
	}

	/**
	 * Allows a configuration of a {@link AuthenticationManager} to be used during SAML 2
	 * authentication. If none is specified, the system will create one inject it into the
	 * {@link Saml2WebSsoAuthenticationFilter}
	 * @param authenticationManager the authentication manager to be used
	 * @return the {@link Saml2LoginConfigurer} for further configuration
	 * @throws IllegalArgumentException if authenticationManager is null configure the
	 * default manager
	 * @since 5.3
	 */
	public Saml2LoginConfigurer<B> authenticationManager(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
		return this;
	}

	/**
	 * Sets the {@code RelyingPartyRegistrationRepository} of relying parties, each party
	 * representing a service provider, SP and this host, and identity provider, IDP pair
	 * that communicate with each other.
	 * @param repo the repository of relying parties
	 * @return the {@link Saml2LoginConfigurer} for further configuration
	 */
	public Saml2LoginConfigurer relyingPartyRegistrationRepository(RelyingPartyRegistrationRepository repo) {
		this.relyingPartyRegistrationRepository = repo;
		return this;
	}

	@Override
	public Saml2LoginConfigurer<B> loginPage(String loginPage) {
		Assert.hasText(loginPage, "loginPage cannot be empty");
		this.loginPage = loginPage;
		return this;
	}

	@Override
	public Saml2LoginConfigurer<B> loginProcessingUrl(String loginProcessingUrl) {
		Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be empty");
		Assert.state(loginProcessingUrl.contains("{registrationId}"), "{registrationId} path variable is required");
		this.loginProcessingUrl = loginProcessingUrl;
		return this;
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl);
	}

	/**
	 * {@inheritDoc}
	 *
	 * Initializes this filter chain for SAML 2 Login. The following actions are taken:
	 * <ul>
	 * <li>The WebSSO endpoint has CSRF disabled, typically {@code /login/saml2/sso}</li>
	 * <li>A {@link Saml2WebSsoAuthenticationFilter is configured}</li>
	 * <li>The {@code loginProcessingUrl} is set</li>
	 * <li>A custom login page is configured, <b>or</b></li>
	 * <li>A default login page with all SAML 2.0 Identity Providers is configured</li>
	 * <li>An {@link AuthenticationProvider} is configured</li>
	 * </ul>
	 */
	@Override
	public void init(B http) throws Exception {
		registerDefaultCsrfOverride(http);
		if (this.relyingPartyRegistrationRepository == null) {
			this.relyingPartyRegistrationRepository = getSharedOrBean(http, RelyingPartyRegistrationRepository.class);
		}
		this.saml2WebSsoAuthenticationFilter = new Saml2WebSsoAuthenticationFilter(getAuthenticationConverter(http),
				this.loginProcessingUrl);
		setAuthenticationFilter(this.saml2WebSsoAuthenticationFilter);
		super.loginProcessingUrl(this.loginProcessingUrl);
		if (StringUtils.hasText(this.loginPage)) {
			// Set custom login page
			super.loginPage(this.loginPage);
			super.init(http);
		}
		else {
			Map<String, String> providerUrlMap = getIdentityProviderUrlMap(
					this.authenticationRequestEndpoint.filterProcessingUrl, this.relyingPartyRegistrationRepository);
			boolean singleProvider = providerUrlMap.size() == 1;
			if (singleProvider) {
				// Setup auto-redirect to provider login page
				// when only 1 IDP is configured
				this.updateAuthenticationDefaults();
				Saml2LogoutConfigurer<B> logoutConfigurer = http.getConfigurer(Saml2LogoutConfigurer.class);
				if (logoutConfigurer != null && !logoutConfigurer.isCustomLogoutSuccess()) {
					logoutConfigurer.logoutSuccessUrl("/login?logout");
				}
				this.updateAccessDefaults(http);
				String loginUrl = providerUrlMap.entrySet().iterator().next().getKey();
				final LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint(loginUrl);
				registerAuthenticationEntryPoint(http, entryPoint);
			}
			else {
				super.init(http);
			}
		}
		this.initDefaultLoginFilter(http);
	}

	/**
	 * {@inheritDoc}
	 *
	 * During the {@code configure} phase, a
	 * {@link Saml2WebSsoAuthenticationRequestFilter} is added to handle SAML 2.0
	 * AuthNRequest redirects
	 */
	@Override
	public void configure(B http) throws Exception {
		http.addFilter(this.authenticationRequestEndpoint.build(http));
		super.configure(http);
		if (this.authenticationManager == null) {
			registerDefaultAuthenticationProvider(http);
		}
		else {
			this.saml2WebSsoAuthenticationFilter.setAuthenticationManager(this.authenticationManager);
		}
	}

	private AuthenticationConverter getAuthenticationConverter(B http) {
		if (this.authenticationConverter == null) {
			return new Saml2AuthenticationTokenConverter(
					new DefaultRelyingPartyRegistrationResolver(this.relyingPartyRegistrationRepository));
		}
		return this.authenticationConverter;
	}

	private void registerDefaultAuthenticationProvider(B http) {
		if (Version.getVersion().startsWith("4")) {
			http.authenticationProvider(postProcess(new OpenSaml4AuthenticationProvider()));
		}
		else {
			http.authenticationProvider(postProcess(new OpenSamlAuthenticationProvider()));
		}
	}

	private void registerDefaultCsrfOverride(B http) {
		CsrfConfigurer<B> csrf = http.getConfigurer(CsrfConfigurer.class);
		if (csrf == null) {
			return;
		}
		csrf.ignoringRequestMatchers(new AntPathRequestMatcher(this.loginProcessingUrl));
	}

	private void initDefaultLoginFilter(B http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter == null || this.isCustomLoginPage()) {
			return;
		}
		loginPageGeneratingFilter.setSaml2LoginEnabled(true);
		loginPageGeneratingFilter.setSaml2AuthenticationUrlToProviderName(this.getIdentityProviderUrlMap(
				this.authenticationRequestEndpoint.filterProcessingUrl, this.relyingPartyRegistrationRepository));
		loginPageGeneratingFilter.setLoginPageUrl(this.getLoginPage());
		loginPageGeneratingFilter.setFailureUrl(this.getFailureUrl());
	}

	@SuppressWarnings("unchecked")
	private Map<String, String> getIdentityProviderUrlMap(String authRequestPrefixUrl,
			RelyingPartyRegistrationRepository idpRepo) {
		Map<String, String> idps = new LinkedHashMap<>();
		if (idpRepo instanceof Iterable) {
			Iterable<RelyingPartyRegistration> repo = (Iterable<RelyingPartyRegistration>) idpRepo;
			repo.forEach((p) -> idps.put(authRequestPrefixUrl.replace("{registrationId}", p.getRegistrationId()),
					p.getRegistrationId()));
		}
		return idps;
	}

	private <C> C getSharedOrBean(B http, Class<C> clazz) {
		C shared = http.getSharedObject(clazz);
		if (shared != null) {
			return shared;
		}
		return getBeanOrNull(http, clazz);
	}

	private <C> C getBeanOrNull(B http, Class<C> clazz) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		if (context == null) {
			return null;
		}
		try {
			return context.getBean(clazz);
		}
		catch (NoSuchBeanDefinitionException ex) {
			return null;
		}
	}

	private <C> void setSharedObject(B http, Class<C> clazz, C object) {
		if (http.getSharedObject(clazz) == null) {
			http.setSharedObject(clazz, object);
		}
	}

	private final class AuthenticationRequestEndpointConfig {

		private String filterProcessingUrl = "/saml2/authenticate/{registrationId}";

		private AuthenticationRequestEndpointConfig() {
		}

		private Filter build(B http) {
			Saml2AuthenticationRequestFactory authenticationRequestResolver = getResolver(http);
			Saml2AuthenticationRequestContextResolver contextResolver = getContextResolver(http);
			return postProcess(
					new Saml2WebSsoAuthenticationRequestFilter(contextResolver, authenticationRequestResolver));
		}

		private Saml2AuthenticationRequestFactory getResolver(B http) {
			Saml2AuthenticationRequestFactory resolver = getSharedOrBean(http, Saml2AuthenticationRequestFactory.class);
			if (resolver == null) {
				if (Version.getVersion().startsWith("4")) {
					return new OpenSaml4AuthenticationRequestFactory();
				}
				return new OpenSamlAuthenticationRequestFactory();
			}
			return resolver;
		}

		private Saml2AuthenticationRequestContextResolver getContextResolver(B http) {
			Saml2AuthenticationRequestContextResolver resolver = getBeanOrNull(http,
					Saml2AuthenticationRequestContextResolver.class);
			if (resolver == null) {
				return new DefaultSaml2AuthenticationRequestContextResolver(new DefaultRelyingPartyRegistrationResolver(
						Saml2LoginConfigurer.this.relyingPartyRegistrationRepository));
			}
			return resolver;
		}

	}

}
