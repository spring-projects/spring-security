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

package org.springframework.security.config.annotation.web.configurers.ott;

import java.util.Collections;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationConverter;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultOneTimeTokenSubmitPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

public final class OneTimeTokenLoginConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<OneTimeTokenLoginConfigurer<H>, H> {

	private final ApplicationContext context;

	private OneTimeTokenService oneTimeTokenService;

	private AuthenticationConverter authenticationConverter = new OneTimeTokenAuthenticationConverter();

	private AuthenticationFailureHandler authenticationFailureHandler;

	private AuthenticationSuccessHandler authenticationSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();

	private String defaultSubmitPageUrl = "/login/ott";

	private boolean submitPageEnabled = true;

	private String loginProcessingUrl = "/login/ott";

	private String tokenGeneratingUrl = "/ott/generate";

	private OneTimeTokenGenerationSuccessHandler oneTimeTokenGenerationSuccessHandler;

	private AuthenticationProvider authenticationProvider;

	public OneTimeTokenLoginConfigurer(ApplicationContext context) {
		this.context = context;
	}

	@Override
	public void init(H http) {
		AuthenticationProvider authenticationProvider = getAuthenticationProvider(http);
		http.authenticationProvider(postProcess(authenticationProvider));
		configureDefaultLoginPage(http);
	}

	private void configureDefaultLoginPage(H http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
			.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter == null) {
			return;
		}
		loginPageGeneratingFilter.setOneTimeTokenEnabled(true);
		loginPageGeneratingFilter.setOneTimeTokenGenerationUrl(this.tokenGeneratingUrl);
		if (this.authenticationFailureHandler == null
				&& StringUtils.hasText(loginPageGeneratingFilter.getLoginPageUrl())) {
			this.authenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler(
					loginPageGeneratingFilter.getLoginPageUrl() + "?error");
		}
	}

	@Override
	public void configure(H http) {
		configureSubmitPage(http);
		configureOttGenerateFilter(http);
		configureOttAuthenticationFilter(http);
	}

	private void configureOttAuthenticationFilter(H http) {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		AuthenticationFilter oneTimeTokenAuthenticationFilter = new AuthenticationFilter(authenticationManager,
				this.authenticationConverter);
		oneTimeTokenAuthenticationFilter.setSecurityContextRepository(getSecurityContextRepository(http));
		oneTimeTokenAuthenticationFilter.setRequestMatcher(antMatcher(HttpMethod.POST, this.loginProcessingUrl));
		oneTimeTokenAuthenticationFilter.setFailureHandler(getAuthenticationFailureHandler());
		oneTimeTokenAuthenticationFilter.setSuccessHandler(this.authenticationSuccessHandler);
		http.addFilter(postProcess(oneTimeTokenAuthenticationFilter));
	}

	private SecurityContextRepository getSecurityContextRepository(H http) {
		SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
		if (securityContextRepository != null) {
			return securityContextRepository;
		}
		return new HttpSessionSecurityContextRepository();
	}

	private void configureOttGenerateFilter(H http) {
		GenerateOneTimeTokenFilter generateFilter = new GenerateOneTimeTokenFilter(getOneTimeTokenService(http),
				getOneTimeTokenGenerationSuccessHandler(http));
		generateFilter.setRequestMatcher(antMatcher(HttpMethod.POST, this.tokenGeneratingUrl));
		http.addFilter(postProcess(generateFilter));
		http.addFilter(DefaultResourcesFilter.css());
	}

	private OneTimeTokenGenerationSuccessHandler getOneTimeTokenGenerationSuccessHandler(H http) {
		if (this.oneTimeTokenGenerationSuccessHandler == null) {
			this.oneTimeTokenGenerationSuccessHandler = getBeanOrNull(http, OneTimeTokenGenerationSuccessHandler.class);
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
		submitPage.setRequestMatcher(antMatcher(HttpMethod.GET, this.defaultSubmitPageUrl));
		submitPage.setLoginProcessingUrl(this.loginProcessingUrl);
		http.addFilter(postProcess(submitPage));
	}

	private AuthenticationProvider getAuthenticationProvider(H http) {
		if (this.authenticationProvider != null) {
			return this.authenticationProvider;
		}
		UserDetailsService userDetailsService = getContext().getBean(UserDetailsService.class);
		this.authenticationProvider = new OneTimeTokenAuthenticationProvider(getOneTimeTokenService(http),
				userDetailsService);
		return this.authenticationProvider;
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
	 * @see org.springframework.security.config.annotation.web.builders.HttpSecurity#csrf(Customizer)
	 */
	public OneTimeTokenLoginConfigurer<H> loginProcessingUrl(String loginProcessingUrl) {
		Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be null or empty");
		this.loginProcessingUrl = loginProcessingUrl;
		return this;
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
		this.authenticationConverter = authenticationConverter;
		return this;
	}

	/**
	 * Specifies the {@link AuthenticationFailureHandler} to use when authentication
	 * fails. The default is redirecting to "/login?error" using
	 * {@link SimpleUrlAuthenticationFailureHandler}
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} to use
	 * when authentication fails.
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationFailureHandler(
			AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
		return this;
	}

	/**
	 * Specifies the {@link AuthenticationSuccessHandler} to be used. The default is
	 * {@link SavedRequestAwareAuthenticationSuccessHandler} with no additional properties
	 * set.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler}.
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationSuccessHandler(
			AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		return this;
	}

	private AuthenticationFailureHandler getAuthenticationFailureHandler() {
		if (this.authenticationFailureHandler != null) {
			return this.authenticationFailureHandler;
		}
		this.authenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler("/login?error");
		return this.authenticationFailureHandler;
	}

	private OneTimeTokenService getOneTimeTokenService(H http) {
		if (this.oneTimeTokenService != null) {
			return this.oneTimeTokenService;
		}
		OneTimeTokenService bean = getBeanOrNull(http, OneTimeTokenService.class);
		if (bean != null) {
			this.oneTimeTokenService = bean;
		}
		else {
			this.oneTimeTokenService = new InMemoryOneTimeTokenService();
		}
		return this.oneTimeTokenService;
	}

	private <C> C getBeanOrNull(H http, Class<C> clazz) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		if (context == null) {
			return null;
		}

		return context.getBeanProvider(clazz).getIfUnique();
	}

	private Map<String, String> hiddenInputs(HttpServletRequest request) {
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		return (token != null) ? Collections.singletonMap(token.getParameterName(), token.getToken())
				: Collections.emptyMap();
	}

	public ApplicationContext getContext() {
		return this.context;
	}

}
