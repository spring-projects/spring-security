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

import java.util.List;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class UrlAuthorizationsTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	@WithMockUser(authorities = "ROLE_USER")
	public void hasAnyAuthorityWhenAuthoritySpecifiedThenMatchesAuthority() throws Exception {
		this.spring.register(RoleConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/role-user-authority"))
				.andExpect(status().isNotFound());
		this.mvc.perform(get("/role-user"))
				.andExpect(status().isNotFound());
		this.mvc.perform(get("/role-admin-authority"))
				.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Test
	@WithMockUser(authorities = "ROLE_ADMIN")
	public void hasAnyAuthorityWhenAuthoritiesSpecifiedThenMatchesAuthority() throws Exception {
		this.spring.register(RoleConfig.class).autowire();
		this.mvc.perform(get("/role-user-admin-authority")).andExpect(status().isNotFound());
		this.mvc.perform(get("/role-user-admin")).andExpect(status().isNotFound());
		this.mvc.perform(get("/role-user-authority")).andExpect(status().isForbidden());
	}

	@Test
	@WithMockUser(roles = "USER")
	public void hasAnyRoleWhenRoleSpecifiedThenMatchesRole() throws Exception {
		this.spring.register(RoleConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/role-user"))
				.andExpect(status().isNotFound());
		this.mvc.perform(get("/role-admin"))
				.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	public void hasAnyRoleWhenRolesSpecifiedThenMatchesRole() throws Exception {
		this.spring.register(RoleConfig.class).autowire();
		this.mvc.perform(get("/role-admin-user")).andExpect(status().isNotFound());
		this.mvc.perform(get("/role-user")).andExpect(status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = "USER")
	public void hasAnyRoleWhenRoleSpecifiedThenDoesNotMatchAuthority() throws Exception {
		this.spring.register(RoleConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/role-user"))
				.andExpect(status().isForbidden());
		this.mvc.perform(get("/role-admin"))
				.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Test
	public void configureWhenNoAccessDecisionManagerThenDefaultsToAffirmativeBased() {
		this.spring.register(NoSpecificAccessDecisionManagerConfig.class).autowire();
		FilterSecurityInterceptor interceptor = getFilter(FilterSecurityInterceptor.class);
		assertThat(interceptor).isNotNull();
		assertThat(interceptor).extracting("accessDecisionManager").isInstanceOf(AffirmativeBased.class);
	}

	private <T extends Filter> T getFilter(Class<T> filterType) {
		FilterChainProxy proxy = this.spring.getContext().getBean(FilterChainProxy.class);
		List<Filter> filters = proxy.getFilters("/");
		for (Filter filter : filters) {
			if (filterType.isAssignableFrom(filter.getClass())) {
				return (T) filter;
			}
		}
		return null;
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class RoleConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.requestMatchers("/role-user-authority").hasAnyAuthority("ROLE_USER")
					.requestMatchers("/role-admin-authority").hasAnyAuthority("ROLE_ADMIN")
					.requestMatchers("/role-user-admin-authority").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
					.requestMatchers("/role-user").hasAnyRole("USER")
					.requestMatchers("/role-admin").hasAnyRole("ADMIN")
					.requestMatchers("/role-user-admin").hasAnyRole("USER", "ADMIN");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class NoSpecificAccessDecisionManagerConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, ApplicationContext context) throws Exception {
			UrlAuthorizationConfigurer<HttpSecurity>.StandardInterceptUrlRegistry registry = http
					.apply(new UrlAuthorizationConfigurer(context)).getRegistry();
			// @formatter:off
			registry
					.requestMatchers("/a").hasRole("ADMIN")
					.anyRequest().hasRole("USER");
			return http.build();
			// @formatter:on
		}

	}

}
