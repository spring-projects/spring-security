/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.annotation.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.ThrowableAssert.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link WebSecurityConfigurerAdapter}.
 *
 * @author Rob Winch
 * @author Joe Grandja
 */
public class WebSecurityConfigurerAdapterTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void loadConfigWhenRequestSecureThenDefaultSecurityHeadersReturned() throws Exception {
		this.spring.register(HeadersArePopulatedByDefaultConfig.class).autowire();

		this.mockMvc.perform(get("/").secure(true)).andExpect(header().string("X-Content-Type-Options", "nosniff"))
				.andExpect(header().string("X-Frame-Options", "DENY"))
				.andExpect(header().string("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"))
				.andExpect(header().string("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string("Pragma", "no-cache")).andExpect(header().string("Expires", "0"))
				.andExpect(header().string("X-XSS-Protection", "1; mode=block"));
	}

	@EnableWebSecurity
	static class HeadersArePopulatedByDefaultConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

		@Override
		protected void configure(HttpSecurity http) {
		}

	}

	@Test
	public void loadConfigWhenRequestAuthenticateThenAuthenticationEventPublished() throws Exception {
		this.spring.register(InMemoryAuthWithWebSecurityConfigurerAdapter.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(status().is3xxRedirection());

		assertThat(InMemoryAuthWithWebSecurityConfigurerAdapter.EVENTS).isNotEmpty();
		assertThat(InMemoryAuthWithWebSecurityConfigurerAdapter.EVENTS).hasSize(1);
	}

	@EnableWebSecurity
	static class InMemoryAuthWithWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter
			implements ApplicationListener<AuthenticationSuccessEvent> {

		static List<AuthenticationSuccessEvent> EVENTS = new ArrayList<>();

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

		@Override
		public void onApplicationEvent(AuthenticationSuccessEvent event) {
			EVENTS.add(event);
		}

	}

	@Test
	public void loadConfigWhenInMemoryConfigureProtectedThenPasswordUpgraded() throws Exception {
		this.spring.register(InMemoryConfigureProtectedConfig.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(status().is3xxRedirection());

		UserDetailsService uds = this.spring.getContext().getBean(UserDetailsService.class);
		assertThat(uds.loadUserByUsername("user").getPassword()).startsWith("{bcrypt}");
	}

	@EnableWebSecurity
	static class InMemoryConfigureProtectedConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

		@Override
		@Bean
		public UserDetailsService userDetailsServiceBean() throws Exception {
			return super.userDetailsServiceBean();
		}

	}

	@Test
	public void loadConfigWhenInMemoryConfigureGlobalThenPasswordUpgraded() throws Exception {
		this.spring.register(InMemoryConfigureGlobalConfig.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(status().is3xxRedirection());

		UserDetailsService uds = this.spring.getContext().getBean(UserDetailsService.class);
		assertThat(uds.loadUserByUsername("user").getPassword()).startsWith("{bcrypt}");
	}

	@EnableWebSecurity
	static class InMemoryConfigureGlobalConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

		@Override
		@Bean
		public UserDetailsService userDetailsServiceBean() throws Exception {
			return super.userDetailsServiceBean();
		}

	}

	@Test
	public void loadConfigWhenCustomContentNegotiationStrategyBeanThenOverridesDefault() {
		OverrideContentNegotiationStrategySharedObjectConfig.CONTENT_NEGOTIATION_STRATEGY_BEAN = mock(
				ContentNegotiationStrategy.class);
		this.spring.register(OverrideContentNegotiationStrategySharedObjectConfig.class).autowire();

		OverrideContentNegotiationStrategySharedObjectConfig securityConfig = this.spring.getContext()
				.getBean(OverrideContentNegotiationStrategySharedObjectConfig.class);

		assertThat(securityConfig.contentNegotiationStrategySharedObject).isNotNull();
		assertThat(securityConfig.contentNegotiationStrategySharedObject)
				.isSameAs(OverrideContentNegotiationStrategySharedObjectConfig.CONTENT_NEGOTIATION_STRATEGY_BEAN);
	}

	@EnableWebSecurity
	static class OverrideContentNegotiationStrategySharedObjectConfig extends WebSecurityConfigurerAdapter {

		static ContentNegotiationStrategy CONTENT_NEGOTIATION_STRATEGY_BEAN;

		private ContentNegotiationStrategy contentNegotiationStrategySharedObject;

		@Bean
		public ContentNegotiationStrategy contentNegotiationStrategy() {
			return CONTENT_NEGOTIATION_STRATEGY_BEAN;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			this.contentNegotiationStrategySharedObject = http.getSharedObject(ContentNegotiationStrategy.class);
			super.configure(http);
		}

	}

	@Test
	public void loadConfigWhenDefaultContentNegotiationStrategyThenHeaderContentNegotiationStrategy() {
		this.spring.register(ContentNegotiationStrategyDefaultSharedObjectConfig.class).autowire();

		ContentNegotiationStrategyDefaultSharedObjectConfig securityConfig = this.spring.getContext()
				.getBean(ContentNegotiationStrategyDefaultSharedObjectConfig.class);

		assertThat(securityConfig.contentNegotiationStrategySharedObject).isNotNull();
		assertThat(securityConfig.contentNegotiationStrategySharedObject)
				.isInstanceOf(HeaderContentNegotiationStrategy.class);
	}

	@EnableWebSecurity
	static class ContentNegotiationStrategyDefaultSharedObjectConfig extends WebSecurityConfigurerAdapter {

		private ContentNegotiationStrategy contentNegotiationStrategySharedObject;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			this.contentNegotiationStrategySharedObject = http.getSharedObject(ContentNegotiationStrategy.class);
			super.configure(http);
		}

	}

	@Test
	public void loadConfigWhenUserDetailsServiceHasCircularReferenceThenStillLoads() {
		this.spring.register(RequiresUserDetailsServiceConfig.class, UserDetailsServiceConfig.class).autowire();

		MyFilter myFilter = this.spring.getContext().getBean(MyFilter.class);

		Throwable thrown = catchThrowable(() -> myFilter.userDetailsService.loadUserByUsername("user"));
		assertThat(thrown).isNull();

		thrown = catchThrowable(() -> myFilter.userDetailsService.loadUserByUsername("admin"));
		assertThat(thrown).isInstanceOf(UsernameNotFoundException.class);
	}

	@Configuration
	static class RequiresUserDetailsServiceConfig {

		@Bean
		public MyFilter myFilter(UserDetailsService userDetailsService) {
			return new MyFilter(userDetailsService);
		}

	}

	@EnableWebSecurity
	static class UserDetailsServiceConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private MyFilter myFilter;

		@Bean
		@Override
		public UserDetailsService userDetailsServiceBean() throws Exception {
			return super.userDetailsServiceBean();
		}

		@Override
		public void configure(HttpSecurity http) {
			http.addFilterBefore(this.myFilter, UsernamePasswordAuthenticationFilter.class);
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	static class MyFilter extends OncePerRequestFilter {

		private UserDetailsService userDetailsService;

		MyFilter(UserDetailsService userDetailsService) {
			this.userDetailsService = userDetailsService;
		}

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
				FilterChain filterChain) throws ServletException, IOException {
			filterChain.doFilter(request, response);
		}

	}

	// SEC-2274: WebSecurityConfigurer adds ApplicationContext as a shared object
	@Test
	public void loadConfigWhenSharedObjectsCreatedThenApplicationContextAdded() {
		this.spring.register(ApplicationContextSharedObjectConfig.class).autowire();

		ApplicationContextSharedObjectConfig securityConfig = this.spring.getContext()
				.getBean(ApplicationContextSharedObjectConfig.class);

		assertThat(securityConfig.applicationContextSharedObject).isNotNull();
		assertThat(securityConfig.applicationContextSharedObject).isSameAs(this.spring.getContext());
	}

	@EnableWebSecurity
	static class ApplicationContextSharedObjectConfig extends WebSecurityConfigurerAdapter {

		private ApplicationContext applicationContextSharedObject;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			this.applicationContextSharedObject = http.getSharedObject(ApplicationContext.class);
			super.configure(http);
		}

	}

	@Test
	public void loadConfigWhenCustomAuthenticationTrustResolverBeanThenOverridesDefault() {
		CustomTrustResolverConfig.AUTHENTICATION_TRUST_RESOLVER_BEAN = mock(AuthenticationTrustResolver.class);
		this.spring.register(CustomTrustResolverConfig.class).autowire();

		CustomTrustResolverConfig securityConfig = this.spring.getContext().getBean(CustomTrustResolverConfig.class);

		assertThat(securityConfig.authenticationTrustResolverSharedObject).isNotNull();
		assertThat(securityConfig.authenticationTrustResolverSharedObject)
				.isSameAs(CustomTrustResolverConfig.AUTHENTICATION_TRUST_RESOLVER_BEAN);
	}

	@EnableWebSecurity
	static class CustomTrustResolverConfig extends WebSecurityConfigurerAdapter {

		static AuthenticationTrustResolver AUTHENTICATION_TRUST_RESOLVER_BEAN;

		private AuthenticationTrustResolver authenticationTrustResolverSharedObject;

		@Bean
		public AuthenticationTrustResolver authenticationTrustResolver() {
			return AUTHENTICATION_TRUST_RESOLVER_BEAN;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			this.authenticationTrustResolverSharedObject = http.getSharedObject(AuthenticationTrustResolver.class);
			super.configure(http);
		}

	}

	@Test
	public void compareOrderWebSecurityConfigurerAdapterWhenLowestOrderToDefaultOrderThenGreaterThanZero() {
		AnnotationAwareOrderComparator comparator = new AnnotationAwareOrderComparator();
		assertThat(comparator.compare(new LowestPriorityWebSecurityConfig(), new DefaultOrderWebSecurityConfig()))
				.isGreaterThan(0);
	}

	static class DefaultOrderWebSecurityConfig extends WebSecurityConfigurerAdapter {

	}

	@Order
	static class LowestPriorityWebSecurityConfig extends WebSecurityConfigurerAdapter {

	}

	// gh-7515
	@Test
	public void performWhenUsingAuthenticationEventPublisherBeanThenUses() throws Exception {
		this.spring.register(CustomAuthenticationEventPublisherBean.class).autowire();

		AuthenticationEventPublisher authenticationEventPublisher = this.spring.getContext()
				.getBean(AuthenticationEventPublisher.class);

		this.mockMvc.perform(get("/").with(httpBasic("user", "password")));

		verify(authenticationEventPublisher).publishAuthenticationSuccess(any(Authentication.class));
	}

	@EnableWebSecurity
	static class CustomAuthenticationEventPublisherBean extends WebSecurityConfigurerAdapter {

		@Bean
		@Override
		public UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

		@Bean
		public AuthenticationEventPublisher authenticationEventPublisher() {
			return mock(AuthenticationEventPublisher.class);
		}

	}

	// gh-4400
	@Test
	public void performWhenUsingAuthenticationEventPublisherInDslThenUses() throws Exception {
		this.spring.register(CustomAuthenticationEventPublisherDsl.class).autowire();

		AuthenticationEventPublisher authenticationEventPublisher = CustomAuthenticationEventPublisherDsl.EVENT_PUBLISHER;

		this.mockMvc.perform(get("/").with(httpBasic("user", "password"))); // fails since
																			// no
																			// providers
																			// configured

		verify(authenticationEventPublisher).publishAuthenticationFailure(any(AuthenticationException.class),
				any(Authentication.class));
	}

	@EnableWebSecurity
	static class CustomAuthenticationEventPublisherDsl extends WebSecurityConfigurerAdapter {

		static AuthenticationEventPublisher EVENT_PUBLISHER = mock(AuthenticationEventPublisher.class);

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.authenticationEventPublisher(EVENT_PUBLISHER);
		}

	}

}
