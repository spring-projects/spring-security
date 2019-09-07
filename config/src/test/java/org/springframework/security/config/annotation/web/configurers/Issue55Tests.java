/*
 * Copyright 2002-2019 the original author or authors.
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

import org.junit.Rule;
import org.junit.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.stereotype.Component;

import javax.servlet.Filter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

import static org.assertj.core.api.Java6Assertions.assertThat;

/**
 * @author Rob Winch
 * @author Konstantin Volivach
 */
public class Issue55Tests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	public void webSecurityConfigurerAdapterDefaultToAutowired() {
		TestingAuthenticationToken token = new TestingAuthenticationToken("test", "this");
		this.spring.register(WebSecurityConfigurerAdapterDefaultsAuthManagerConfig.class);
		this.spring.getContext().getBean(FilterChainProxy.class);

		FilterSecurityInterceptor filter = (FilterSecurityInterceptor) findFilter(FilterSecurityInterceptor.class, 0);
		assertThat(filter.getAuthenticationManager().authenticate(token)).isEqualTo(CustomAuthenticationManager.RESULT);
	}


	@EnableWebSecurity
	static class WebSecurityConfigurerAdapterDefaultsAuthManagerConfig {
		@Component
		public static class WebSecurityAdapter extends WebSecurityConfigurerAdapter {

			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
						.authorizeRequests()
						.anyRequest().hasRole("USER");
			}
		}

		@Configuration
		public static class AuthenticationManagerConfiguration {
			@Bean
			public AuthenticationManager authenticationManager() throws Exception {
				return new CustomAuthenticationManager();
			}
		}
	}

	@Test
	public void multiHttpWebSecurityConfigurerAdapterDefaultsToAutowired() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		TestingAuthenticationToken token = new TestingAuthenticationToken("test", "this");
		this.spring.register(MultiWebSecurityConfigurerAdapterDefaultsAuthManagerConfig.class);
		this.spring.getContext().getBean(FilterChainProxy.class);

		FilterSecurityInterceptor filter = (FilterSecurityInterceptor) findFilter(FilterSecurityInterceptor.class, 0);
		assertThat(filter.getAuthenticationManager().authenticate(token)).isEqualTo(CustomAuthenticationManager.RESULT);

		FilterSecurityInterceptor secondFilter = (FilterSecurityInterceptor) findFilter(FilterSecurityInterceptor.class, 1);
		assertThat(secondFilter.getAuthenticationManager().authenticate(token)).isEqualTo(CustomAuthenticationManager.RESULT);
	}

	private AuthenticationManager getAuthManager(AbstractAuthenticationProcessingFilter filter) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		final Method getAuthenticationManager = filter.getClass().getDeclaredMethod("getAuthenticationManager");
		getAuthenticationManager.setAccessible(true);
		return (AuthenticationManager) getAuthenticationManager.invoke(filter);
	}

	@EnableWebSecurity
	static class MultiWebSecurityConfigurerAdapterDefaultsAuthManagerConfig {
		@Component
		@Order(1)
		public static class ApiWebSecurityAdapter extends WebSecurityConfigurerAdapter {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
						.antMatcher("/api/**")
						.authorizeRequests()
						.anyRequest().hasRole("USER");
			}
		}

		@Component
		public static class WebSecurityAdapter extends WebSecurityConfigurerAdapter {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http
						.authorizeRequests()
						.anyRequest().hasRole("USER");
			}
		}

		@Configuration
		public static class AuthenticationManagerConfiguration {
			@Bean
			public AuthenticationManager authenticationManager() throws Exception {
				return new CustomAuthenticationManager();
			}
		}
	}

	static class CustomAuthenticationManager implements AuthenticationManager {
		static Authentication RESULT = new TestingAuthenticationToken("test", "this", "ROLE_USER");

		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return RESULT;
		}
	}

	protected Filter findFilter(Class<?> filter, int index) {
		List<Filter> filters = filterChain(index).getFilters();
		for (Filter it : filters) {
			if (filter.isAssignableFrom(it.getClass())) {
				return it;
			}
		}
		return null;
	}

	SecurityFilterChain filterChain(int index) {
		return this.spring.getContext().getBean(FilterChainProxy.class).getFilterChains().get(index);
	}
}
