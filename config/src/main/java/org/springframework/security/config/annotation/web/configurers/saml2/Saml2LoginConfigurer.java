/*
 * Copyright 2004-present the original author or authors.
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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.opensaml.core.Version;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthorities;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.OpenSaml5AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml5AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.ParameterRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatchers;
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
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link RelyingPartyRegistrationRepository} (required)</li>
 * <li>{@link DefaultLoginPageGeneratingFilter} - if {@link #loginPage(String)} is not
 * configured and {@code DefaultLoginPageGeneratingFilter} is available, than a default
 * login page will be made available</li>
 * </ul>
 *
 * @since 5.2
 * @see HttpSecurity#saml2Login(Customizer)
 * @see Saml2WebSsoAuthenticationFilter
 * @see Saml2WebSsoAuthenticationRequestFilter
 * @see RelyingPartyRegistrationRepository
 * @see AbstractAuthenticationFilterConfigurer
 */
public final class Saml2LoginConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractAuthenticationFilterConfigurer<B, Saml2LoginConfigurer<B>, Saml2WebSsoAuthenticationFilter> {

	private static final boolean USE_OPENSAML_5 = Version.getVersion().startsWith("5");

	private String loginPage;

	private String authenticationRequestUri = "/saml2/authenticate";

	private String[] authenticationRequestParams = { "registrationId={registrationId}" };

	private RequestMatcher authenticationRequestMatcher;

	private Saml2AuthenticationRequestResolver authenticationRequestResolver;

	private RequestMatcher loginProcessingUrl;

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
	public Saml2LoginConfigurer<B> relyingPartyRegistrationRepository(RelyingPartyRegistrationRepository repo) {
		this.relyingPartyRegistrationRepository = repo;
		return this;
	}

	@Override
	public Saml2LoginConfigurer<B> loginPage(String loginPage) {
		Assert.hasText(loginPage, "loginPage cannot be empty");
		this.loginPage = loginPage;
		return this;
	}

	/**
	 * Use this {@link Saml2AuthenticationRequestResolver} for generating SAML 2.0
	 * Authentication Requests.
	 * @param authenticationRequestResolver
	 * @return the {@link Saml2LoginConfigurer} for further configuration
	 * @since 5.7
	 */
	public Saml2LoginConfigurer<B> authenticationRequestResolver(
			Saml2AuthenticationRequestResolver authenticationRequestResolver) {
		Assert.notNull(authenticationRequestResolver, "authenticationRequestResolver cannot be null");
		this.authenticationRequestResolver = authenticationRequestResolver;
		return this;
	}

	/**
	 * Customize the URL that the SAML Authentication Request will be sent to.
	 * @param authenticationRequestUri the URI to use for the SAML 2.0 Authentication
	 * Request
	 * @return the {@link Saml2LoginConfigurer} for further configuration
	 * @since 6.0
	 * @deprecated Use {@link #authenticationRequestUriQuery} instead
	 */
	@Deprecated
	public Saml2LoginConfigurer<B> authenticationRequestUri(String authenticationRequestUri) {
		return authenticationRequestUriQuery(authenticationRequestUri);
	}

	/**
	 * Customize the URL that the SAML Authentication Request will be sent to. This method
	 * also supports query parameters like so: <pre>
	 * 	authenticationRequestUriQuery("/saml/authenticate?registrationId={registrationId}")
	 * </pre> {@link RelyingPartyRegistrations}
	 * @param authenticationRequestUriQuery the URI and query to use for the SAML 2.0
	 * Authentication Request
	 * @return the {@link Saml2LoginConfigurer} for further configuration
	 * @since 6.0
	 */
	public Saml2LoginConfigurer<B> authenticationRequestUriQuery(String authenticationRequestUriQuery) {
		Assert.state(authenticationRequestUriQuery.contains("{registrationId}"),
				"authenticationRequestUri must contain {registrationId} path variable or query value");
		String[] parts = authenticationRequestUriQuery.split("[?&]");
		this.authenticationRequestUri = parts[0];
		this.authenticationRequestParams = new String[parts.length - 1];
		System.arraycopy(parts, 1, this.authenticationRequestParams, 0, parts.length - 1);
		this.authenticationRequestMatcher = new PathQueryRequestMatcher(
				getRequestMatcherBuilder().matcher(this.authenticationRequestUri), this.authenticationRequestParams);
		return this;
	}

	/**
	 * Specifies the URL to validate the credentials. If specified a custom URL, consider
	 * specifying a custom {@link AuthenticationConverter} via
	 * {@link #authenticationConverter(AuthenticationConverter)}, since the default
	 * {@link AuthenticationConverter} implementation relies on the
	 * <code>{registrationId}</code> path variable to be present in the URL
	 * @param loginProcessingUrl the URL to validate the credentials
	 * @return the {@link Saml2LoginConfigurer} for additional customization
	 * @see Saml2WebSsoAuthenticationFilter#DEFAULT_FILTER_PROCESSES_URI
	 */
	@Override
	public Saml2LoginConfigurer<B> loginProcessingUrl(String loginProcessingUrl) {
		Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be empty");
		this.loginProcessingUrl = getRequestMatcherBuilder().matcher(loginProcessingUrl);
		return this;
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return getRequestMatcherBuilder().matcher(loginProcessingUrl);
	}

	/**
	 * {@inheritDoc}
	 * <p>
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
	public void init(B http) {
		registerDefaultCsrfOverride(http);
		relyingPartyRegistrationRepository(http);
		this.saml2WebSsoAuthenticationFilter = new Saml2WebSsoAuthenticationFilter(getAuthenticationConverter(http));
		this.saml2WebSsoAuthenticationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		this.saml2WebSsoAuthenticationFilter.setRequiresAuthenticationRequestMatcher(getLoginProcessingEndpoint());
		setAuthenticationRequestRepository(http, this.saml2WebSsoAuthenticationFilter);
		setAuthenticationFilter(this.saml2WebSsoAuthenticationFilter);
		if (StringUtils.hasText(this.loginPage)) {
			// Set custom login page
			super.loginPage(this.loginPage);
			super.init(http);
		}
		else {
			Map<String, String> providerUrlMap = getIdentityProviderUrlMap(this.authenticationRequestUri,
					this.authenticationRequestParams, this.relyingPartyRegistrationRepository);
			boolean singleProvider = providerUrlMap.size() == 1;
			if (singleProvider) {
				// Setup auto-redirect to provider login page
				// when only 1 IDP is configured
				this.updateAuthenticationDefaults();
				this.updateAccessDefaults(http);
				String loginUrl = providerUrlMap.entrySet().iterator().next().getKey();
				registerAuthenticationEntryPoint(http, getLoginEntryPoint(http, loginUrl));
			}
			else {
				super.init(http);
			}
		}
		this.initDefaultLoginFilter(http);
		if (this.authenticationManager == null) {
			registerDefaultAuthenticationProvider(http);
		}
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * During the {@code configure} phase, a
	 * {@link Saml2WebSsoAuthenticationRequestFilter} is added to handle SAML 2.0
	 * AuthNRequest redirects
	 */
	@Override
	public void configure(B http) {
		Saml2WebSsoAuthenticationRequestFilter filter = getAuthenticationRequestFilter(http);
		filter.setAuthenticationRequestRepository(getAuthenticationRequestRepository(http));
		http.addFilter(postProcess(filter));
		super.configure(http);
		if (this.authenticationManager != null) {
			this.saml2WebSsoAuthenticationFilter.setAuthenticationManager(this.authenticationManager);
		}
	}

	RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(B http) {
		if (this.relyingPartyRegistrationRepository == null) {
			this.relyingPartyRegistrationRepository = getSharedOrBean(http, RelyingPartyRegistrationRepository.class);
		}
		return this.relyingPartyRegistrationRepository;
	}

	private AuthenticationEntryPoint getLoginEntryPoint(B http, String providerLoginPage) {
		RequestMatcher loginPageMatcher = getRequestMatcherBuilder().matcher(this.getLoginPage());
		RequestMatcher faviconMatcher = getRequestMatcherBuilder().matcher("/favicon.ico");
		RequestMatcher defaultEntryPointMatcher = this.getAuthenticationEntryPointMatcher(http);
		RequestMatcher defaultLoginPageMatcher = new AndRequestMatcher(
				new OrRequestMatcher(loginPageMatcher, faviconMatcher), defaultEntryPointMatcher);
		RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
				new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));
		LoginUrlAuthenticationEntryPoint loginUrlEntryPoint = new LoginUrlAuthenticationEntryPoint(providerLoginPage);
		RequestMatcher loginUrlMatcher = new AndRequestMatcher(notXRequestedWith,
				new NegatedRequestMatcher(defaultLoginPageMatcher));
		// @formatter:off
		AuthenticationEntryPoint loginEntryPoint = DelegatingAuthenticationEntryPoint.builder()
				.addEntryPointFor(loginUrlEntryPoint, loginUrlMatcher)
				.defaultEntryPoint(getAuthenticationEntryPoint())
				.build();
		// @formatter:on
		ExceptionHandlingConfigurer<B> exceptions = http.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptions != null) {
			RequestMatcher requestMatcher = getAuthenticationEntryPointMatcher(http);
			exceptions.defaultDeniedHandlerForMissingAuthority(
					(ep) -> ep.addEntryPointFor(loginEntryPoint, requestMatcher),
					GrantedAuthorities.FACTOR_SAML_RESPONSE_AUTHORITY);
		}
		return loginEntryPoint;
	}

	private void setAuthenticationRequestRepository(B http,
			Saml2WebSsoAuthenticationFilter saml2WebSsoAuthenticationFilter) {
		saml2WebSsoAuthenticationFilter.setAuthenticationRequestRepository(getAuthenticationRequestRepository(http));
	}

	private Saml2WebSsoAuthenticationRequestFilter getAuthenticationRequestFilter(B http) {
		Saml2AuthenticationRequestResolver authenticationRequestResolver = getAuthenticationRequestResolver(http);
		return new Saml2WebSsoAuthenticationRequestFilter(authenticationRequestResolver);
	}

	private Saml2AuthenticationRequestResolver getAuthenticationRequestResolver(B http) {
		if (this.authenticationRequestResolver != null) {
			return this.authenticationRequestResolver;
		}
		Saml2AuthenticationRequestResolver bean = getBeanOrNull(http, Saml2AuthenticationRequestResolver.class);
		if (bean != null) {
			return bean;
		}
		if (USE_OPENSAML_5) {
			OpenSaml5AuthenticationRequestResolver openSamlAuthenticationRequestResolver = new OpenSaml5AuthenticationRequestResolver(
					relyingPartyRegistrationRepository(http));
			openSamlAuthenticationRequestResolver.setRequestMatcher(getAuthenticationRequestMatcher());
			return openSamlAuthenticationRequestResolver;
		}
		else {
			throw new IllegalArgumentException(
					"Spring Security does not support OpenSAML " + Version.getVersion() + ". Please use OpenSAML 5");
		}
	}

	private RequestMatcher getAuthenticationRequestMatcher() {
		if (this.authenticationRequestMatcher == null) {
			this.authenticationRequestMatcher = RequestMatchers.anyOf(
					getRequestMatcherBuilder()
						.matcher(Saml2AuthenticationRequestResolver.DEFAULT_AUTHENTICATION_REQUEST_URI),
					new PathQueryRequestMatcher(getRequestMatcherBuilder().matcher(this.authenticationRequestUri),
							this.authenticationRequestParams));
		}
		return this.authenticationRequestMatcher;
	}

	private RequestMatcher getLoginProcessingEndpoint() {
		if (this.loginProcessingUrl == null) {
			this.loginProcessingUrl = RequestMatchers.anyOf(
					getRequestMatcherBuilder().matcher(Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI),
					getRequestMatcherBuilder().matcher("/login/saml2/sso"));
		}

		return this.loginProcessingUrl;
	}

	private AuthenticationConverter getAuthenticationConverter(B http) {
		if (this.authenticationConverter != null) {
			return this.authenticationConverter;
		}
		AuthenticationConverter authenticationConverterBean = getBeanOrNull(http,
				Saml2AuthenticationTokenConverter.class);
		if (authenticationConverterBean != null) {
			return authenticationConverterBean;
		}
		if (USE_OPENSAML_5) {
			authenticationConverterBean = getBeanOrNull(http, OpenSaml5AuthenticationTokenConverter.class);
			if (authenticationConverterBean != null) {
				return authenticationConverterBean;
			}
			OpenSaml5AuthenticationTokenConverter converter = new OpenSaml5AuthenticationTokenConverter(
					this.relyingPartyRegistrationRepository);
			converter.setAuthenticationRequestRepository(getAuthenticationRequestRepository(http));
			converter.setRequestMatcher(getLoginProcessingEndpoint());
			return converter;
		}
		throw new IllegalArgumentException(
				"Spring Security does not support OpenSAML " + Version.getVersion() + ". Please use OpenSAML 5");
	}

	private void registerDefaultAuthenticationProvider(B http) {
		if (USE_OPENSAML_5) {
			OpenSaml5AuthenticationProvider provider = getBeanOrNull(http, OpenSaml5AuthenticationProvider.class);
			if (provider == null) {
				http.authenticationProvider(postProcess(new OpenSaml5AuthenticationProvider()));
			}
		}
		else {
			throw new IllegalArgumentException(
					"Spring Security does not support OpenSAML " + Version.getVersion() + ". Please use OpenSAML 5");
		}
	}

	private void registerDefaultCsrfOverride(B http) {
		CsrfConfigurer<B> csrf = http.getConfigurer(CsrfConfigurer.class);
		if (csrf == null) {
			return;
		}
		csrf.ignoringRequestMatchers(getLoginProcessingEndpoint());
	}

	private void initDefaultLoginFilter(B http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
			.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter == null || this.isCustomLoginPage()) {
			return;
		}
		loginPageGeneratingFilter.setSaml2LoginEnabled(true);
		loginPageGeneratingFilter
			.setSaml2AuthenticationUrlToProviderName(this.getIdentityProviderUrlMap(this.authenticationRequestUri,
					this.authenticationRequestParams, this.relyingPartyRegistrationRepository));
		loginPageGeneratingFilter.setLoginPageUrl(this.getLoginPage());
		loginPageGeneratingFilter.setFailureUrl(this.getFailureUrl());
	}

	@SuppressWarnings("unchecked")
	private Map<String, String> getIdentityProviderUrlMap(String authRequestPrefixUrl, String[] authRequestQueryParams,
			RelyingPartyRegistrationRepository idpRepo) {
		Map<String, String> idps = new LinkedHashMap<>();
		if (idpRepo instanceof Iterable) {
			Iterable<RelyingPartyRegistration> repo = (Iterable<RelyingPartyRegistration>) idpRepo;
			StringBuilder authRequestQuery = new StringBuilder("?");
			for (String authRequestQueryParam : authRequestQueryParams) {
				authRequestQuery.append(authRequestQueryParam + "&");
			}
			authRequestQuery.deleteCharAt(authRequestQuery.length() - 1);
			String authenticationRequestUriQuery = authRequestPrefixUrl + authRequestQuery;
			repo.forEach(
					(p) -> idps.put(authenticationRequestUriQuery.replace("{registrationId}", p.getRegistrationId()),
							p.getRegistrationId()));
		}
		return idps;
	}

	private Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> getAuthenticationRequestRepository(
			B http) {
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> repository = getBeanOrNull(http,
				Saml2AuthenticationRequestRepository.class);
		if (repository == null) {
			return new HttpSessionSaml2AuthenticationRequestRepository();
		}
		return repository;
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
		return context.getBeanProvider(clazz).getIfUnique();
	}

	private <C> void setSharedObject(B http, Class<C> clazz, C object) {
		if (http.getSharedObject(clazz) == null) {
			http.setSharedObject(clazz, object);
		}
	}

	static class PathQueryRequestMatcher implements RequestMatcher {

		private final RequestMatcher matcher;

		PathQueryRequestMatcher(RequestMatcher pathMatcher, String... params) {
			List<RequestMatcher> matchers = new ArrayList<>();
			matchers.add(pathMatcher);
			for (String param : params) {
				String[] parts = param.split("=");
				if (parts.length == 1) {
					matchers.add(new ParameterRequestMatcher(parts[0]));
				}
				else {
					matchers.add(new ParameterRequestMatcher(parts[0], parts[1]));
				}
			}
			this.matcher = new AndRequestMatcher(matchers);
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return matcher(request).isMatch();
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			return this.matcher.matcher(request);
		}

	}

}
