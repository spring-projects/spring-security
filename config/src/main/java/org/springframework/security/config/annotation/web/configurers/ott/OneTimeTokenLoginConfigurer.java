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

package org.springframework.security.config.annotation.web.configurers.ott;

import java.util.Collections;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthorities;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ott.DefaultGenerateOneTimeTokenRequestResolver;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenRequestResolver;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationConverter;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationFilter;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultOneTimeTokenSubmitPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AbstractHttpConfigurer} for One-Time Token Login.
 *
 * <p>
 * One-Time Token Login provides an application with the capability to have users log in
 * by obtaining a single-use token out of band, for example through email.
 *
 * <p>
 * Defaults are provided for all configuration options, with the only required
 * configuration being
 * {@link #tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler)}.
 * Alternatively, a {@link OneTimeTokenGenerationSuccessHandler} {@code @Bean} may be
 * registered instead.
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter}s are populated:
 *
 * <ul>
 * <li>{@link DefaultOneTimeTokenSubmitPageGeneratingFilter}</li>
 * <li>{@link GenerateOneTimeTokenFilter}</li>
 * <li>{@link OneTimeTokenAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link DefaultLoginPageGeneratingFilter} - if {@link #loginPage(String)} is not
 * configured and {@code DefaultLoginPageGeneratingFilter} is available, then a default
 * login page will be made available</li>
 * </ul>
 *
 * @author Marcus Da Coregio
 * @author Daniel Garnier-Moiroux
 * @since 6.4
 * @see HttpSecurity#oneTimeTokenLogin(Customizer)
 * @see DefaultOneTimeTokenSubmitPageGeneratingFilter
 * @see GenerateOneTimeTokenFilter
 * @see OneTimeTokenAuthenticationFilter
 * @see AbstractAuthenticationFilterConfigurer
 */
public final class OneTimeTokenLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractAuthenticationFilterConfigurer<H, OneTimeTokenLoginConfigurer<H>, OneTimeTokenAuthenticationFilter> {

	private final ApplicationContext context;

	private OneTimeTokenService oneTimeTokenService;

	private String defaultSubmitPageUrl = DefaultOneTimeTokenSubmitPageGeneratingFilter.DEFAULT_SUBMIT_PAGE_URL;

	private boolean submitPageEnabled = true;

	private String loginProcessingUrl = OneTimeTokenAuthenticationFilter.DEFAULT_LOGIN_PROCESSING_URL;

	private String tokenGeneratingUrl = GenerateOneTimeTokenFilter.DEFAULT_GENERATE_URL;

	private OneTimeTokenGenerationSuccessHandler oneTimeTokenGenerationSuccessHandler;

	private AuthenticationProvider authenticationProvider;

	private GenerateOneTimeTokenRequestResolver requestResolver;

	public OneTimeTokenLoginConfigurer(ApplicationContext context) {
		super(new OneTimeTokenAuthenticationFilter(), null);
		this.context = context;
	}

	@Override
	public void init(H http) {
		if (getLoginProcessingUrl() == null) {
			loginProcessingUrl(OneTimeTokenAuthenticationFilter.DEFAULT_LOGIN_PROCESSING_URL);
		}
		super.init(http);
		AuthenticationProvider authenticationProvider = getAuthenticationProvider();
		http.authenticationProvider(postProcess(authenticationProvider));
		intiDefaultLoginFilter(http);
		ExceptionHandlingConfigurer<H> exceptions = http.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptions != null) {
			AuthenticationEntryPoint entryPoint = getAuthenticationEntryPoint();
			RequestMatcher requestMatcher = getAuthenticationEntryPointMatcher(http);
			exceptions.defaultDeniedHandlerForMissingAuthority((ep) -> ep.addEntryPointFor(entryPoint, requestMatcher),
					GrantedAuthorities.FACTOR_OTT_AUTHORITY);
		}
	}

	private void intiDefaultLoginFilter(H http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
			.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter == null || isCustomLoginPage()) {
			return;
		}
		loginPageGeneratingFilter.setOneTimeTokenEnabled(true);
		loginPageGeneratingFilter.setOneTimeTokenGenerationUrl(this.tokenGeneratingUrl);

		if (!StringUtils.hasText(loginPageGeneratingFilter.getLoginPageUrl())) {
			loginPageGeneratingFilter.setLoginPageUrl(DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL);
			loginPageGeneratingFilter.setFailureUrl(DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL + "?"
					+ DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME);
			loginPageGeneratingFilter
				.setLogoutSuccessUrl(DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL + "?logout");
		}
	}

	@Override
	public void configure(H http) {
		super.configure(http);
		configureSubmitPage(http);
		configureOttGenerateFilter(http);
	}

	private void configureOttGenerateFilter(H http) {
		GenerateOneTimeTokenFilter generateFilter = new GenerateOneTimeTokenFilter(getOneTimeTokenService(),
				getOneTimeTokenGenerationSuccessHandler());
		generateFilter.setRequestMatcher(getRequestMatcherBuilder().matcher(HttpMethod.POST, this.tokenGeneratingUrl));
		generateFilter.setRequestResolver(getGenerateRequestResolver());
		http.addFilter(postProcess(generateFilter));
		http.addFilter(DefaultResourcesFilter.css());
	}

	private OneTimeTokenGenerationSuccessHandler getOneTimeTokenGenerationSuccessHandler() {
		if (this.oneTimeTokenGenerationSuccessHandler == null) {
			this.oneTimeTokenGenerationSuccessHandler = this.context
				.getBeanProvider(OneTimeTokenGenerationSuccessHandler.class)
				.getIfUnique();
		}
		if (this.oneTimeTokenGenerationSuccessHandler == null) {
			throw new IllegalStateException("""
					A OneTimeTokenGenerationSuccessHandler is required to enable oneTimeTokenLogin().
					Please provide it as a bean or pass it to the oneTimeTokenLogin() DSL.
					""");
		}
		return this.oneTimeTokenGenerationSuccessHandler;
	}

	private void configureSubmitPage(H http) {
		if (!this.submitPageEnabled) {
			return;
		}
		DefaultOneTimeTokenSubmitPageGeneratingFilter submitPage = new DefaultOneTimeTokenSubmitPageGeneratingFilter();
		submitPage.setResolveHiddenInputs(this::hiddenInputs);
		submitPage.setRequestMatcher(getRequestMatcherBuilder().matcher(HttpMethod.GET, this.defaultSubmitPageUrl));
		submitPage.setLoginProcessingUrl(this.getLoginProcessingUrl());
		http.addFilter(postProcess(submitPage));
	}

	private AuthenticationProvider getAuthenticationProvider() {
		if (this.authenticationProvider != null) {
			return this.authenticationProvider;
		}
		UserDetailsService userDetailsService = this.context.getBean(UserDetailsService.class);
		this.authenticationProvider = new OneTimeTokenAuthenticationProvider(getOneTimeTokenService(),
				userDetailsService);
		return this.authenticationProvider;
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return getRequestMatcherBuilder().matcher(HttpMethod.POST, loginProcessingUrl);
	}

	/**
	 * Specifies the {@link AuthenticationProvider} to use when authenticating the user.
	 * @param authenticationProvider
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProvider = authenticationProvider;
		return this;
	}

	/**
	 * Specifies the URL that a One-Time Token generate request will be processed.
	 * Defaults to {@code /ott/generate}.
	 * @param tokenGeneratingUrl
	 */
	public OneTimeTokenLoginConfigurer<H> tokenGeneratingUrl(String tokenGeneratingUrl) {
		Assert.hasText(tokenGeneratingUrl, "tokenGeneratingUrl cannot be null or empty");
		this.tokenGeneratingUrl = tokenGeneratingUrl;
		return this;
	}

	/**
	 * Specifies strategy to be used to handle generated one-time tokens.
	 * @param oneTimeTokenGenerationSuccessHandler
	 */
	public OneTimeTokenLoginConfigurer<H> tokenGenerationSuccessHandler(
			OneTimeTokenGenerationSuccessHandler oneTimeTokenGenerationSuccessHandler) {
		Assert.notNull(oneTimeTokenGenerationSuccessHandler, "oneTimeTokenGenerationSuccessHandler cannot be null");
		this.oneTimeTokenGenerationSuccessHandler = oneTimeTokenGenerationSuccessHandler;
		return this;
	}

	/**
	 * Specifies the URL to process the login request, defaults to {@code /login/ott}.
	 * Only POST requests are processed, for that reason make sure that you pass a valid
	 * CSRF token if CSRF protection is enabled.
	 * @param loginProcessingUrl
	 * @see HttpSecurity#csrf(Customizer)
	 */
	public OneTimeTokenLoginConfigurer<H> loginProcessingUrl(String loginProcessingUrl) {
		Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be null or empty");
		super.loginProcessingUrl(loginProcessingUrl);
		return this;
	}

	/**
	 * Specifies the URL to send users to if login is required. If used with
	 * {@link EnableWebSecurity} a default login page will be generated when this
	 * attribute is not specified.
	 * @param loginPage
	 */
	@Override
	public OneTimeTokenLoginConfigurer<H> loginPage(String loginPage) {
		return super.loginPage(loginPage);
	}

	/**
	 * Configures whether the default one-time token submit page should be shown. This
	 * will prevent the {@link DefaultOneTimeTokenSubmitPageGeneratingFilter} to be
	 * configured.
	 * @param show
	 */
	public OneTimeTokenLoginConfigurer<H> showDefaultSubmitPage(boolean show) {
		this.submitPageEnabled = show;
		return this;
	}

	/**
	 * Sets the URL that the default submit page will be generated. Defaults to
	 * {@code /login/ott}. If you don't want to generate the default submit page you
	 * should use {@link #showDefaultSubmitPage(boolean)}. Note that this method always
	 * invoke {@link #showDefaultSubmitPage(boolean)} passing {@code true}.
	 * @param submitPageUrl
	 */
	public OneTimeTokenLoginConfigurer<H> defaultSubmitPageUrl(String submitPageUrl) {
		Assert.hasText(submitPageUrl, "submitPageUrl cannot be null or empty");
		this.defaultSubmitPageUrl = submitPageUrl;
		showDefaultSubmitPage(true);
		return this;
	}

	/**
	 * Configures the {@link OneTimeTokenService} used to generate and consume
	 * {@link OneTimeToken}
	 * @param oneTimeTokenService
	 */
	public OneTimeTokenLoginConfigurer<H> tokenService(OneTimeTokenService oneTimeTokenService) {
		Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
		this.oneTimeTokenService = oneTimeTokenService;
		return this;
	}

	/**
	 * Use this {@link AuthenticationConverter} when converting incoming requests to an
	 * {@link Authentication}. By default, the {@link OneTimeTokenAuthenticationConverter}
	 * is used.
	 * @param authenticationConverter the {@link AuthenticationConverter} to use
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.getAuthenticationFilter().setAuthenticationConverter(authenticationConverter);
		return this;
	}

	/**
	 * Specifies the {@link AuthenticationFailureHandler} to use when authentication
	 * fails. The default is redirecting to "/login?error" using
	 * {@link SimpleUrlAuthenticationFailureHandler}
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} to use
	 * when authentication fails.
	 * @deprecated Use {@link #failureHandler(AuthenticationFailureHandler)} instead
	 */
	@Deprecated(since = "6.5")
	public OneTimeTokenLoginConfigurer<H> authenticationFailureHandler(
			AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		super.failureHandler(authenticationFailureHandler);
		return this;
	}

	/**
	 * Specifies the {@link AuthenticationSuccessHandler} to be used. The default is
	 * {@link SavedRequestAwareAuthenticationSuccessHandler} with no additional properties
	 * set.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler}.
	 * @deprecated Use {@link #successHandler(AuthenticationSuccessHandler)} instead
	 */
	@Deprecated(since = "6.5")
	public OneTimeTokenLoginConfigurer<H> authenticationSuccessHandler(
			AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		super.successHandler(authenticationSuccessHandler);
		return this;
	}

	/**
	 * Use this {@link GenerateOneTimeTokenRequestResolver} when resolving
	 * {@link GenerateOneTimeTokenRequest} from {@link HttpServletRequest}. By default,
	 * the {@link DefaultGenerateOneTimeTokenRequestResolver} is used.
	 * @param requestResolver the {@link GenerateOneTimeTokenRequestResolver}
	 * @since 6.5
	 */
	public OneTimeTokenLoginConfigurer<H> generateRequestResolver(GenerateOneTimeTokenRequestResolver requestResolver) {
		Assert.notNull(requestResolver, "requestResolver cannot be null");
		this.requestResolver = requestResolver;
		return this;
	}

	private GenerateOneTimeTokenRequestResolver getGenerateRequestResolver() {
		if (this.requestResolver != null) {
			return this.requestResolver;
		}
		this.requestResolver = this.context.getBeanProvider(GenerateOneTimeTokenRequestResolver.class)
			.getIfUnique(DefaultGenerateOneTimeTokenRequestResolver::new);
		return this.requestResolver;
	}

	private OneTimeTokenService getOneTimeTokenService() {
		if (this.oneTimeTokenService != null) {
			return this.oneTimeTokenService;
		}
		this.oneTimeTokenService = this.context.getBeanProvider(OneTimeTokenService.class)
			.getIfUnique(InMemoryOneTimeTokenService::new);
		return this.oneTimeTokenService;
	}

	private Map<String, String> hiddenInputs(HttpServletRequest request) {
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		return (token != null) ? Collections.singletonMap(token.getParameterName(), token.getToken())
				: Collections.emptyMap();
	}

	/**
	 * @deprecated Use this.context instead
	 */
	@Deprecated
	public ApplicationContext getContext() {
		return this.context;
	}

}
