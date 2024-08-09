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

package org.springframework.security.config.annotation.web.configurers.passwordless;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.passwordless.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.passwordless.ott.OneTimeTokenAuthenticationProvider;
import org.springframework.security.authentication.passwordless.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.passwordless.PasswordlessAuthenticationFilter;
import org.springframework.security.web.authentication.passwordless.ott.OneTimeTokenAuthenticationConverter;
import org.springframework.security.web.authentication.passwordless.ott.OneTimeTokenAuthenticationRequestFilter;
import org.springframework.security.web.authentication.passwordless.ott.OneTimeTokenAuthenticationRequestSuccessHandler;
import org.springframework.security.web.authentication.passwordless.ott.RedirectOneTimeTokenAuthenticationRequestSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultOneTimeTokenConfirmationPageGeneratingFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;

public final class PasswordlessLoginConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<PasswordlessLoginConfigurer<H>, H> {

	private final ApplicationContext context;

	private final List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

	private OneTimeTokenConfigurer oneTimeTokenConfigurer;

	public PasswordlessLoginConfigurer(ApplicationContext context) {
		this.context = context;
	}

	@Override
	public void init(H builder) throws Exception {
		if (this.oneTimeTokenConfigurer != null) {
			this.oneTimeTokenConfigurer.init(builder);
		}
	}

	@Override
	public void configure(H http) throws Exception {
		if (this.oneTimeTokenConfigurer != null) {
			this.oneTimeTokenConfigurer.configure(http);
		}
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		DelegatingAuthenticationConverter authenticationConverter = getAuthenticationConverter();
		http.addFilter(new PasswordlessAuthenticationFilter(authenticationManager, authenticationConverter));
	}

	public PasswordlessLoginConfigurer<H> oneTimeToken(
			Customizer<OneTimeTokenConfigurer> oneTimeTokenConfigurerCustomizer) {
		if (this.oneTimeTokenConfigurer == null) {
			this.oneTimeTokenConfigurer = new OneTimeTokenConfigurer();
		}
		oneTimeTokenConfigurerCustomizer.customize(this.oneTimeTokenConfigurer);
		return this;
	}

	private DelegatingAuthenticationConverter getAuthenticationConverter() {
		if (this.authenticationConverters.isEmpty()) {
			throw new IllegalStateException(
					"No authentication converters configured for passwordless login. Please configure at least one passwordless login method");
		}
		return new DelegatingAuthenticationConverter(this.authenticationConverters);
	}

	public ApplicationContext getContext() {
		return this.context;
	}

	public final class OneTimeTokenConfigurer {

		private OneTimeTokenAuthenticationRequestSuccessHandler successHandler = new RedirectOneTimeTokenAuthenticationRequestSuccessHandler(
				"/login/ott");

		private OneTimeTokenService oneTimeTokenService;

		private AuthenticationConverter authenticationConverter;

		private void init(H http) {
			UserDetailsService userDetailsService = getContext().getBean(UserDetailsService.class);
			OneTimeTokenAuthenticationProvider authenticationProvider = new OneTimeTokenAuthenticationProvider(
					getOneTimeTokenService(http), userDetailsService);
			http.authenticationProvider(postProcess(authenticationProvider));
			PasswordlessLoginConfigurer.this.authenticationConverters.add(getAuthenticationConverter());
			initDefaultLoginPage(http);
		}

		private void initDefaultLoginPage(H http) {
			DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
			if (loginPageGeneratingFilter != null) {
				loginPageGeneratingFilter.setOneTimeTokenEnabled(true);
			}
		}

		private void configure(H http) {
			OneTimeTokenAuthenticationRequestFilter authenticationRequestFilter = new OneTimeTokenAuthenticationRequestFilter(
					getOneTimeTokenService(http));
			authenticationRequestFilter.setSuccessHandler(this.successHandler);
			http.addFilterBefore(postProcess(authenticationRequestFilter), UsernamePasswordAuthenticationFilter.class);

			DefaultOneTimeTokenConfirmationPageGeneratingFilter confirmationPage = new DefaultOneTimeTokenConfirmationPageGeneratingFilter();
			confirmationPage.setResolveHiddenInputs(this::hiddenInputs);
			http.addFilterBefore(postProcess(confirmationPage), DefaultLoginPageGeneratingFilter.class);
		}

		public void authenticationRequestSuccessHandler(
				OneTimeTokenAuthenticationRequestSuccessHandler authenticationRequestSuccessHandler) {
			Assert.notNull(authenticationRequestSuccessHandler, "authenticationRequestSuccessHandler cannot be null");
			this.successHandler = authenticationRequestSuccessHandler;
		}

		public void oneTimeTokenService(OneTimeTokenService oneTimeTokenService) {
			Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
			this.oneTimeTokenService = oneTimeTokenService;
		}

		public void authenticationConverter(AuthenticationConverter authenticationConverter) {
			Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
			this.authenticationConverter = authenticationConverter;
		}

		private AuthenticationConverter getAuthenticationConverter() {
			if (this.authenticationConverter == null) {
				this.authenticationConverter = new OneTimeTokenAuthenticationConverter();
			}
			return this.authenticationConverter;
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
			try {
				return context.getBean(clazz);
			}
			catch (NoSuchBeanDefinitionException ex) {
				return null;
			}
		}

		private Map<String, String> hiddenInputs(HttpServletRequest request) {
			CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
			return (token != null) ? Collections.singletonMap(token.getParameterName(), token.getToken())
					: Collections.emptyMap();
		}

	}

}
