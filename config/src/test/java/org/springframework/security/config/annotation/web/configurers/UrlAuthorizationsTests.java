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

import java.util.List;

import javax.servlet.Filter;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SecurityTestExecutionListeners
public class UrlAuthorizationsTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

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
		this.mvc.perform(get("/role-user-admin-authority"))
				.andExpect(status().isNotFound());
		this.mvc.perform(get("/role-user-admin"))
				.andExpect(status().isNotFound());
		this.mvc.perform(get("/role-user-authority"))
				.andExpect(status().isForbidden());
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
		this.mvc.perform(get("/role-admin-user"))
				.andExpect(status().isNotFound());
		this.mvc.perform(get("/role-user"))
				.andExpect(status().isForbidden());
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

	@EnableWebSecurity
	static class RoleConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/role-user-authority").hasAnyAuthority("ROLE_USER")
					.antMatchers("/role-admin-authority").hasAnyAuthority("ROLE_ADMIN")
					.antMatchers("/role-user-admin-authority").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
					.antMatchers("/role-user").hasAnyRole("USER")
					.antMatchers("/role-admin").hasAnyRole("ADMIN")
					.antMatchers("/role-user-admin").hasAnyRole("USER", "ADMIN");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class NoSpecificAccessDecisionManagerConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			ApplicationContext context = getApplicationContext();
			UrlAuthorizationConfigurer<HttpSecurity>.StandardInterceptUrlRegistry registry = http
					.apply(new UrlAuthorizationConfigurer(context)).getRegistry();
			// @formatter:off
			registry
					.antMatchers("/a").hasRole("ADMIN")
					.anyRequest().hasRole("USER");
			// @formatter:on
		}

	}

}
