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
package org.springframework.security.config.annotation.method.configuration;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.Serializable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Demonstrate the samples
 *
 * @author Rob Winch
 *
 */
public class SampleEnableGlobalMethodSecurityTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MethodSecurityService methodSecurityService;

	@Before
	public void setup() {
		SecurityContextHolder.getContext().setAuthentication(
									new TestingAuthenticationToken("user", "password", "ROLE_USER"));
	}

	@Test
	public void preAuthorize() {
		this.spring.register(SampleWebSecurityConfig.class).autowire();

		assertThat(this.methodSecurityService.secured()).isNull();
		assertThat(this.methodSecurityService.jsr250()).isNull();

		assertThatThrownBy(() -> this.methodSecurityService.preAuthorize())
			.isInstanceOf(AccessDeniedException.class);
	}

	@EnableGlobalMethodSecurity(prePostEnabled=true)
	static class SampleWebSecurityConfig {
		@Bean
		public MethodSecurityService methodSecurityService() {
			return new MethodSecurityServiceImpl();
		}

		@Autowired
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER").and()
					.withUser("admin").password("password").roles("USER", "ADMIN");
		}
	}


	@Test
	public void customPermissionHandler() {
		this.spring.register(CustomPermissionEvaluatorWebSecurityConfig.class).autowire();

		assertThat(this.methodSecurityService.hasPermission("allowed")).isNull();

		assertThatThrownBy(() -> this.methodSecurityService.hasPermission("denied"))
			.isInstanceOf(AccessDeniedException.class);
	}


	@EnableGlobalMethodSecurity(prePostEnabled=true)
	public static class CustomPermissionEvaluatorWebSecurityConfig extends GlobalMethodSecurityConfiguration {
		@Bean
		public MethodSecurityService methodSecurityService() {
			return new MethodSecurityServiceImpl();
		}

		@Override
		protected MethodSecurityExpressionHandler createExpressionHandler() {
			DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
			expressionHandler.setPermissionEvaluator(new CustomPermissionEvaluator());
			return expressionHandler;
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
				.withUser("user").password("password").roles("USER").and()
				.withUser("admin").password("password").roles("USER", "ADMIN");
		}
	}

	static class CustomPermissionEvaluator implements PermissionEvaluator {
		public boolean hasPermission(Authentication authentication,
				Object targetDomainObject, Object permission) {
			return !"denied".equals(targetDomainObject);
		}

		public boolean hasPermission(Authentication authentication,
				Serializable targetId, String targetType, Object permission) {
			return !"denied".equals(targetId);
		}

	}
}
