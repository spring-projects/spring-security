/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.csrf.CsrfToken;

import java.util.Collections;

/**
 * Adds a Filter that will generate a login page if one is not specified otherwise when
 * using {@link WebSecurityConfigurerAdapter}.
 *
 * <p>
 * By default an
 * {@link org.springframework.security.web.access.channel.InsecureChannelProcessor} and a
 * {@link org.springframework.security.web.access.channel.SecureChannelProcessor} will be
 * registered.
 * </p>
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are conditionally populated
 *
 * <ul>
 * <li>{@link DefaultLoginPageGeneratingFilter} if the {@link FormLoginConfigurer} did not
 * have a login page specified</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created. isLogoutRequest <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link org.springframework.security.web.PortMapper} is used to create the default
 * {@link org.springframework.security.web.access.channel.ChannelProcessor} instances</li>
 * <li>{@link FormLoginConfigurer} is used to determine if the
 * {@link DefaultLoginPageConfigurer} should be added and how to configure it.</li>
 * </ul>
 *
 * @see WebSecurityConfigurerAdapter
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class DefaultLoginPageConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<DefaultLoginPageConfigurer<H>, H> {

	private DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = new DefaultLoginPageGeneratingFilter();

	@Override
	public void init(H http) throws Exception {
		this.loginPageGeneratingFilter.setResolveHiddenInputs( request -> {
			CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
			if(token == null) {
				return Collections.emptyMap();
			}
			return Collections.singletonMap(token.getParameterName(), token.getToken());
		});
		http.setSharedObject(DefaultLoginPageGeneratingFilter.class,
				loginPageGeneratingFilter);
	}

	@Override
	@SuppressWarnings("unchecked")
	public void configure(H http) throws Exception {
		AuthenticationEntryPoint authenticationEntryPoint = null;
		ExceptionHandlingConfigurer<?> exceptionConf = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionConf != null) {
			authenticationEntryPoint = exceptionConf.getAuthenticationEntryPoint();
		}

		if (loginPageGeneratingFilter.isEnabled() && authenticationEntryPoint == null) {
			loginPageGeneratingFilter = postProcess(loginPageGeneratingFilter);
			http.addFilter(loginPageGeneratingFilter);
		}
	}

}