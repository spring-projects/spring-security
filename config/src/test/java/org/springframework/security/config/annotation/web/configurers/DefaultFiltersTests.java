/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.servlet.Filter;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.TestHttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @author Konstantin Volivach
 */
@ExtendWith(SpringTestContextExtension.class)
public class DefaultFiltersTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void defaultTheWebSecurityConfigurerAdapter() {
		this.spring.register(FilterChainProxyBuilderMissingConfig.class);
		assertThat(this.spring.getContext().getBean(FilterChainProxy.class)).isNotNull();
	}

	@Test
	public void nullWebInvocationPrivilegeEvaluator() {
		this.spring.register(NullWebInvocationPrivilegeEvaluatorConfig.class, UserDetailsServiceConfig.class);
		List<SecurityFilterChain> filterChains = this.spring.getContext().getBean(FilterChainProxy.class)
				.getFilterChains();
		assertThat(filterChains.size()).isEqualTo(1);
		DefaultSecurityFilterChain filterChain = (DefaultSecurityFilterChain) filterChains.get(0);
		assertThat(filterChain.getRequestMatcher()).isInstanceOf(AnyRequestMatcher.class);
		assertThat(filterChain.getFilters().size()).isEqualTo(1);
		long filter = filterChain.getFilters().stream()
				.filter((it) -> it instanceof UsernamePasswordAuthenticationFilter).count();
		assertThat(filter).isEqualTo(1);
	}

	@Test
	public void filterChainProxyBuilderIgnoringResources() {
		this.spring.register(FilterChainProxyBuilderIgnoringConfig.class, UserDetailsServiceConfig.class);
		List<SecurityFilterChain> filterChains = this.spring.getContext().getBean(FilterChainProxy.class)
				.getFilterChains();
		assertThat(filterChains.size()).isEqualTo(2);
		DefaultSecurityFilterChain firstFilter = (DefaultSecurityFilterChain) filterChains.get(0);
		DefaultSecurityFilterChain secondFilter = (DefaultSecurityFilterChain) filterChains.get(1);
		assertThat(firstFilter.getFilters().isEmpty()).isEqualTo(true);
		assertThat(secondFilter.getRequestMatcher()).isInstanceOf(AnyRequestMatcher.class);
		List<? extends Class<? extends Filter>> classes = secondFilter.getFilters().stream().map(Filter::getClass)
				.collect(Collectors.toList());
		assertThat(classes.contains(WebAsyncManagerIntegrationFilter.class)).isTrue();
		assertThat(classes.contains(SecurityContextHolderFilter.class)).isTrue();
		assertThat(classes.contains(HeaderWriterFilter.class)).isTrue();
		assertThat(classes.contains(LogoutFilter.class)).isTrue();
		assertThat(classes.contains(CsrfFilter.class)).isTrue();
		assertThat(classes.contains(RequestCacheAwareFilter.class)).isTrue();
		assertThat(classes.contains(SecurityContextHolderAwareRequestFilter.class)).isTrue();
		assertThat(classes.contains(AnonymousAuthenticationFilter.class)).isTrue();
		assertThat(classes.contains(ExceptionTranslationFilter.class)).isTrue();
		assertThat(classes.contains(FilterSecurityInterceptor.class)).isTrue();
	}

	@Test
	public void defaultFiltersPermitAll() throws IOException, ServletException {
		this.spring.register(DefaultFiltersConfigPermitAll.class, UserDetailsServiceConfig.class);
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "");
		request.setServletPath("/logout");
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "BaseSpringSpec_CSRFTOKEN");
		CsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.saveToken(csrfToken, request, response);
		CsrfTokenRequestHandler handler = new XorCsrfTokenRequestAttributeHandler();
		handler.handle(request, response, () -> csrfToken);
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		request.setParameter(token.getParameterName(), token.getToken());
		this.spring.getContext().getBean("springSecurityFilterChain", Filter.class).doFilter(request, response,
				new MockFilterChain());
		assertThat(response.getRedirectedUrl()).isEqualTo("/login?logout");
	}

	@Configuration
	@EnableWebSecurity
	static class FilterChainProxyBuilderMissingConfig {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	static class UserDetailsServiceConfig {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user(), PasswordEncodedUser.admin());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NullWebInvocationPrivilegeEvaluatorConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			TestHttpSecurity.disableDefaults(http);
			http.formLogin();
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class FilterChainProxyBuilderIgnoringConfig {

		@Bean
		WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.ignoring().requestMatchers("/resources/**");
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultFiltersConfigPermitAll {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

	}

}
