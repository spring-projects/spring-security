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

package org.springframework.security.config.annotation.sec2758;

import jakarta.annotation.security.RolesAllowed;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 *
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class Sec2758Tests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Autowired(required = false)
	Service service;

	@WithMockUser(authorities = "CUSTOM")
	@Test
	public void requestWhenNullifyingRolePrefixThenPassivityRestored() throws Exception {
		this.spring.register(SecurityConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@WithMockUser(authorities = "CUSTOM")
	@Test
	public void methodSecurityWhenNullifyingRolePrefixThenPassivityRestored() {
		this.spring.register(SecurityConfig.class).autowire();
		this.service.doJsr250();
		this.service.doPreAuthorize();
	}

	@Configuration
	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true, jsr250Enabled = true)
	static class SecurityConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
			.authorizeRequests()
			.anyRequest().access("hasAnyRole('CUSTOM')");
			return http.build();
			// @formatter:on
		}

		@Bean
		Service service() {
			return new Service();
		}

		@Bean
		static DefaultRolesPrefixPostProcessor defaultRolesPrefixPostProcessor() {
			return new DefaultRolesPrefixPostProcessor();
		}

		@RestController
		static class RootController {

			@GetMapping("/")
			String ok() {
				return "ok";
			}

		}

	}

	static class Service {

		@PreAuthorize("hasRole('CUSTOM')")
		void doPreAuthorize() {
		}

		@RolesAllowed("CUSTOM")
		void doJsr250() {
		}

	}

	static class DefaultRolesPrefixPostProcessor implements BeanPostProcessor, PriorityOrdered {

		@Override
		public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
			if (bean instanceof Jsr250MethodSecurityMetadataSource) {
				((Jsr250MethodSecurityMetadataSource) bean).setDefaultRolePrefix(null);
			}
			if (bean instanceof DefaultMethodSecurityExpressionHandler) {
				((DefaultMethodSecurityExpressionHandler) bean).setDefaultRolePrefix(null);
			}
			if (bean instanceof DefaultWebSecurityExpressionHandler) {
				((DefaultWebSecurityExpressionHandler) bean).setDefaultRolePrefix(null);
			}
			return bean;
		}

		@Override
		public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
			return bean;
		}

		@Override
		public int getOrder() {
			return Ordered.HIGHEST_PRECEDENCE;
		}

	}

}
