/*
 * Copyright 2002-2021 the original author or authors.
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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.JdkRegexpMethodPointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.annotation.BusinessService;
import org.springframework.security.access.annotation.ExpressionProtectedBusinessServiceImpl;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.method.AuthorizationManagerMethodBeforeAdvice;
import org.springframework.security.access.method.AuthorizationMethodAfterAdvice;
import org.springframework.security.access.method.AuthorizationMethodBeforeAdvice;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link MethodSecurityConfiguration}.
 *
 * @author Evgeniy Cheban
 */
@RunWith(SpringRunner.class)
@SecurityTestExecutionListeners
public class MethodSecurityConfigurationTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired(required = false)
	MethodSecurityService methodSecurityService;

	@Autowired(required = false)
	BusinessService businessService;

	@WithMockUser(roles = "ADMIN")
	@Test
	public void preAuthorizeWhenRoleAdminThenAccessDeniedException() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::preAuthorize)
				.withMessage("Access Denied");
	}

	@WithAnonymousUser
	@Test
	public void preAuthorizePermitAllWhenRoleAnonymousThenPasses() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		String result = this.methodSecurityService.preAuthorizePermitAll();
		assertThat(result).isNull();
	}

	@WithAnonymousUser
	@Test
	public void preAuthorizeNotAnonymousWhenRoleAnonymousThenAccessDeniedException() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(this.methodSecurityService::preAuthorizeNotAnonymous).withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void preAuthorizeNotAnonymousWhenRoleUserThenPasses() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		this.methodSecurityService.preAuthorizeNotAnonymous();
	}

	@WithMockUser
	@Test
	public void securedWhenRoleUserThenAccessDeniedException() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::secured)
				.withMessage("Access Denied");
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void securedWhenRoleAdminThenPasses() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		String result = this.methodSecurityService.secured();
		assertThat(result).isNull();
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void securedUserWhenRoleAdminThenAccessDeniedException() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::securedUser)
				.withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void securedUserWhenRoleUserThenPasses() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		String result = this.methodSecurityService.securedUser();
		assertThat(result).isNull();
	}

	@WithMockUser
	@Test
	public void preAuthorizeAdminWhenRoleUserThenAccessDeniedException() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::preAuthorizeAdmin)
				.withMessage("Access Denied");
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void preAuthorizeAdminWhenRoleAdminThenPasses() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		this.methodSecurityService.preAuthorizeAdmin();
	}

	@WithMockUser
	@Test
	public void postHasPermissionWhenParameterIsNotGrantThenAccessDeniedException() {
		this.spring.register(CustomPermissionEvaluatorConfig.class, MethodSecurityServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.methodSecurityService.postHasPermission("deny")).withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void postHasPermissionWhenParameterIsGrantThenPasses() {
		this.spring.register(CustomPermissionEvaluatorConfig.class, MethodSecurityServiceConfig.class).autowire();
		String result = this.methodSecurityService.postHasPermission("grant");
		assertThat(result).isNull();
	}

	@WithMockUser
	@Test
	public void postAnnotationWhenParameterIsNotGrantThenAccessDeniedException() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.methodSecurityService.postAnnotation("deny")).withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void postAnnotationWhenParameterIsGrantThenPasses() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		String result = this.methodSecurityService.postAnnotation("grant");
		assertThat(result).isNull();
	}

	@WithMockUser("bob")
	@Test
	public void methodReturningAListWhenPrePostFiltersConfiguredThenFiltersList() {
		this.spring.register(BusinessServiceConfig.class).autowire();
		List<String> names = new ArrayList<>();
		names.add("bob");
		names.add("joe");
		names.add("sam");
		List<?> result = this.businessService.methodReturningAList(names);
		assertThat(result).hasSize(1);
		assertThat(result.get(0)).isEqualTo("bob");
	}

	@WithMockUser("bob")
	@Test
	public void methodReturningAnArrayWhenPostFilterConfiguredThenFiltersArray() {
		this.spring.register(BusinessServiceConfig.class).autowire();
		List<String> names = new ArrayList<>();
		names.add("bob");
		names.add("joe");
		names.add("sam");
		Object[] result = this.businessService.methodReturningAnArray(names.toArray());
		assertThat(result).hasSize(1);
		assertThat(result[0]).isEqualTo("bob");
	}

	@WithMockUser("bob")
	@Test
	public void securedUserWhenCustomBeforeAdviceConfiguredAndNameBobThenPasses() {
		this.spring.register(CustomAuthorizationManagerBeforeAdviceConfig.class, MethodSecurityServiceConfig.class)
				.autowire();
		String result = this.methodSecurityService.securedUser();
		assertThat(result).isNull();
	}

	@WithMockUser("joe")
	@Test
	public void securedUserWhenCustomBeforeAdviceConfiguredAndNameNotBobThenAccessDeniedException() {
		this.spring.register(CustomAuthorizationManagerBeforeAdviceConfig.class, MethodSecurityServiceConfig.class)
				.autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::securedUser)
				.withMessage("Access Denied");
	}

	@WithMockUser("bob")
	@Test
	public void securedUserWhenCustomAfterAdviceConfiguredAndNameBobThenGranted() {
		this.spring.register(CustomAuthorizationManagerAfterAdviceConfig.class, MethodSecurityServiceConfig.class)
				.autowire();
		String result = this.methodSecurityService.securedUser();
		assertThat(result).isEqualTo("granted");
	}

	@WithMockUser("joe")
	@Test
	public void securedUserWhenCustomAfterAdviceConfiguredAndNameNotBobThenAccessDeniedException() {
		this.spring.register(CustomAuthorizationManagerAfterAdviceConfig.class, MethodSecurityServiceConfig.class)
				.autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::securedUser)
				.withMessage("Access Denied for User 'joe'");
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void jsr250WhenRoleAdminThenAccessDeniedException() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::jsr250)
				.withMessage("Access Denied");
	}

	@WithAnonymousUser
	@Test
	public void jsr250PermitAllWhenRoleAnonymousThenPasses() {
		this.spring.register(MethodSecurityServiceConfig.class).autowire();
		String result = this.methodSecurityService.jsr250PermitAll();
		assertThat(result).isNull();
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void rolesAllowedUserWhenRoleAdminThenAccessDeniedException() {
		this.spring.register(BusinessServiceConfig.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.businessService::rolesAllowedUser)
				.withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void rolesAllowedUserWhenRoleUserThenPasses() {
		this.spring.register(BusinessServiceConfig.class).autowire();
		this.businessService.rolesAllowedUser();
	}

	@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
	static class MethodSecurityServiceConfig {

		@Bean
		MethodSecurityService methodSecurityService() {
			return new MethodSecurityServiceImpl();
		}

	}

	@EnableMethodSecurity(jsr250Enabled = true)
	static class BusinessServiceConfig {

		@Bean
		BusinessService businessService() {
			return new ExpressionProtectedBusinessServiceImpl();
		}

	}

	@EnableMethodSecurity
	static class CustomPermissionEvaluatorConfig {

		@Bean
		MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
			DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
			expressionHandler.setPermissionEvaluator(new PermissionEvaluator() {
				@Override
				public boolean hasPermission(Authentication authentication, Object targetDomainObject,
						Object permission) {
					return "grant".equals(targetDomainObject);
				}

				@Override
				public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
						Object permission) {
					throw new UnsupportedOperationException();
				}
			});
			return expressionHandler;
		}

	}

	@EnableMethodSecurity
	static class CustomAuthorizationManagerBeforeAdviceConfig {

		@Bean
		AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> customBeforeAdvice() {
			JdkRegexpMethodPointcut methodMatcher = new JdkRegexpMethodPointcut();
			methodMatcher.setPattern(".*MethodSecurityServiceImpl.*securedUser");
			AuthorizationManager<MethodAuthorizationContext> authorizationManager = (a,
					o) -> new AuthorizationDecision("bob".equals(a.get().getName()));
			return new AuthorizationManagerMethodBeforeAdvice<>(methodMatcher, authorizationManager);
		}

	}

	@EnableMethodSecurity
	static class CustomAuthorizationManagerAfterAdviceConfig {

		@Bean
		AuthorizationMethodAfterAdvice<MethodAuthorizationContext> customAfterAdvice() {
			JdkRegexpMethodPointcut methodMatcher = new JdkRegexpMethodPointcut();
			methodMatcher.setPattern(".*MethodSecurityServiceImpl.*securedUser");
			return new AuthorizationMethodAfterAdvice<MethodAuthorizationContext>() {
				@Override
				public MethodMatcher getMethodMatcher() {
					return methodMatcher;
				}

				@Override
				public Object after(Supplier<Authentication> authentication,
						MethodAuthorizationContext methodAuthorizationContext, Object returnedObject) {
					Authentication auth = authentication.get();
					if ("bob".equals(auth.getName())) {
						return "granted";
					}
					throw new AccessDeniedException("Access Denied for User '" + auth.getName() + "'");
				}
			};
		}

	}

}
