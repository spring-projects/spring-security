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

package org.springframework.security.config.method;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.annotation.BusinessService;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.method.configuration.MethodSecurityService;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.verify;

/**
 * @author Josh Cummings
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class MethodSecurityBeanDefinitionParserTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/method/MethodSecurityBeanDefinitionParserTests";

	private final UsernamePasswordAuthenticationToken bob = UsernamePasswordAuthenticationToken.unauthenticated("bob",
			"bobspassword");

	@Autowired(required = false)
	MethodSecurityService methodSecurityService;

	@Autowired(required = false)
	BusinessService businessService;

	public final SpringTestContext spring = new SpringTestContext(this);

	@WithMockUser(roles = "ADMIN")
	@Test
	public void preAuthorizeWhenRoleAdminThenAccessDeniedException() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::preAuthorize)
				.withMessage("Access Denied");
	}

	@Test
	public void configureWhenAspectJThenRegistersAspects() {
		this.spring.configLocations(xml("AspectJMethodSecurityServiceEnabled")).autowire();
		assertThat(this.spring.getContext().containsBean("preFilterAspect$0")).isTrue();
		assertThat(this.spring.getContext().containsBean("postFilterAspect$0")).isTrue();
		assertThat(this.spring.getContext().containsBean("preAuthorizeAspect$0")).isTrue();
		assertThat(this.spring.getContext().containsBean("postAuthorizeAspect$0")).isTrue();
		assertThat(this.spring.getContext().containsBean("securedAspect$0")).isTrue();
		assertThat(this.spring.getContext().containsBean("annotationSecurityAspect$0")).isFalse();
	}

	@WithAnonymousUser
	@Test
	public void preAuthorizePermitAllWhenRoleAnonymousThenPasses() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		String result = this.methodSecurityService.preAuthorizePermitAll();
		assertThat(result).isNull();
	}

	@WithAnonymousUser
	@Test
	public void preAuthorizeNotAnonymousWhenRoleAnonymousThenAccessDeniedException() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(this.methodSecurityService::preAuthorizeNotAnonymous).withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void preAuthorizeNotAnonymousWhenRoleUserThenPasses() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		this.methodSecurityService.preAuthorizeNotAnonymous();
	}

	@WithMockUser
	@Test
	public void securedWhenRoleUserThenAccessDeniedException() {
		this.spring.configLocations(xml("MethodSecurityServiceEnabled")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::secured)
				.withMessage("Access Denied");
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void securedWhenRoleAdminThenPasses() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		String result = this.methodSecurityService.secured();
		assertThat(result).isNull();
	}

	@Test
	public void securedWhenCustomSecurityContextHolderStrategyThenUses() {
		this.spring.configLocations(xml("MethodSecurityServiceEnabledCustomSecurityContextHolderStrategy")).autowire();
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		SecurityContext context = new SecurityContextImpl(new TestingAuthenticationToken("user", "pass"));
		strategy.setContext(context);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::secured)
				.withMessage("Access Denied");
		verify(strategy).getContext();
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void securedUserWhenRoleAdminThenAccessDeniedException() {
		this.spring.configLocations(xml("MethodSecurityServiceEnabled")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::securedUser)
				.withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void securedUserWhenRoleUserThenPasses() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		String result = this.methodSecurityService.securedUser();
		assertThat(result).isNull();
	}

	@WithMockUser
	@Test
	public void preAuthorizeAdminWhenRoleUserThenAccessDeniedException() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::preAuthorizeAdmin)
				.withMessage("Access Denied");
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void preAuthorizeAdminWhenRoleAdminThenPasses() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		this.methodSecurityService.preAuthorizeAdmin();
	}

	@Test
	public void preAuthorizeWhenCustomSecurityContextHolderStrategyThenUses() {
		this.spring.configLocations(xml("MethodSecurityServiceEnabledCustomSecurityContextHolderStrategy")).autowire();
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		SecurityContext context = new SecurityContextImpl(new TestingAuthenticationToken("user", "pass"));
		strategy.setContext(context);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::preAuthorizeAdmin)
				.withMessage("Access Denied");
		verify(strategy).getContext();
	}

	@WithMockUser(authorities = "PREFIX_ADMIN")
	@Test
	public void preAuthorizeAdminWhenRoleAdminAndCustomPrefixThenPasses() {
		this.spring.configLocations(xml("CustomGrantedAuthorityDefaults")).autowire();
		this.methodSecurityService.preAuthorizeAdmin();
	}

	@WithMockUser
	@Test
	public void postHasPermissionWhenParameterIsNotGrantThenAccessDeniedException() {
		this.spring.configLocations(xml("CustomPermissionEvaluator")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.methodSecurityService.postHasPermission("deny")).withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void postHasPermissionWhenParameterIsGrantThenPasses() {
		this.spring.configLocations(xml("CustomPermissionEvaluator")).autowire();
		String result = this.methodSecurityService.postHasPermission("grant");
		assertThat(result).isNull();
	}

	@WithMockUser
	@Test
	public void postAnnotationWhenParameterIsNotGrantThenAccessDeniedException() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.methodSecurityService.postAnnotation("deny")).withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void postAnnotationWhenParameterIsGrantThenPasses() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		String result = this.methodSecurityService.postAnnotation("grant");
		assertThat(result).isNull();
	}

	@Test
	public void preFilterWhenCustomSecurityContextHolderStrategyThenUses() {
		this.spring.configLocations(xml("MethodSecurityServiceEnabledCustomSecurityContextHolderStrategy")).autowire();
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		SecurityContext context = new SecurityContextImpl(new TestingAuthenticationToken("user", "pass"));
		strategy.setContext(context);
		List<String> result = this.methodSecurityService
				.preFilterByUsername(new ArrayList<>(Arrays.asList("user", "bob", "joe")));
		assertThat(result).containsExactly("user");
		verify(strategy).getContext();
	}

	@Test
	public void postFilterWhenCustomSecurityContextHolderStrategyThenUses() {
		this.spring.configLocations(xml("MethodSecurityServiceEnabledCustomSecurityContextHolderStrategy")).autowire();
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		SecurityContext context = new SecurityContextImpl(new TestingAuthenticationToken("user", "pass"));
		strategy.setContext(context);
		List<String> result = this.methodSecurityService
				.postFilterByUsername(new ArrayList<>(Arrays.asList("user", "bob", "joe")));
		assertThat(result).containsExactly("user");
		verify(strategy).getContext();
	}

	@WithMockUser("bob")
	@Test
	public void methodReturningAListWhenPrePostFiltersConfiguredThenFiltersList() {
		this.spring.configLocations(xml("BusinessService")).autowire();
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
		this.spring.configLocations(xml("BusinessService")).autowire();
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
		this.spring.configLocations(xml("CustomAuthorizationManagerBeforeAdvice")).autowire();
		String result = this.methodSecurityService.securedUser();
		assertThat(result).isNull();
	}

	@WithMockUser("joe")
	@Test
	public void securedUserWhenCustomBeforeAdviceConfiguredAndNameNotBobThenAccessDeniedException() {
		this.spring.configLocations(xml("CustomAuthorizationManagerBeforeAdvice")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::securedUser)
				.withMessage("Access Denied");
	}

	@WithMockUser("bob")
	@Test
	public void securedUserWhenCustomAfterAdviceConfiguredAndNameBobThenGranted() {
		this.spring.configLocations(xml("CustomAuthorizationManagerAfterAdvice")).autowire();
		String result = this.methodSecurityService.securedUser();
		assertThat(result).isEqualTo("granted");
	}

	@WithMockUser("joe")
	@Test
	public void securedUserWhenCustomAfterAdviceConfiguredAndNameNotBobThenAccessDeniedException() {
		this.spring.configLocations(xml("CustomAuthorizationManagerAfterAdvice")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::securedUser)
				.withMessage("Access Denied for User 'joe'");
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void jsr250WhenRoleAdminThenAccessDeniedException() {
		this.spring.configLocations(xml("MethodSecurityServiceEnabled")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.methodSecurityService::jsr250)
				.withMessage("Access Denied");
	}

	@Test
	public void jsr250WhenCustomSecurityContextHolderStrategyThenUses() {
		this.spring.configLocations(xml("MethodSecurityServiceEnabledCustomSecurityContextHolderStrategy")).autowire();
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		SecurityContext context = new SecurityContextImpl(new TestingAuthenticationToken("user", "pass"));
		strategy.setContext(context);
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(this.methodSecurityService::jsr250RolesAllowed).withMessage("Access Denied");
		verify(strategy).getContext();
	}

	@WithAnonymousUser
	@Test
	public void jsr250PermitAllWhenRoleAnonymousThenPasses() {
		this.spring.configLocations(xml("MethodSecurityServiceEnabled")).autowire();
		String result = this.methodSecurityService.jsr250PermitAll();
		assertThat(result).isNull();
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void rolesAllowedUserWhenRoleAdminThenAccessDeniedException() {
		this.spring.configLocations(xml("BusinessService")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.businessService::rolesAllowedUser)
				.withMessage("Access Denied");
	}

	@WithMockUser
	@Test
	public void rolesAllowedUserWhenRoleUserThenPasses() {
		this.spring.configLocations(xml("BusinessService")).autowire();
		this.businessService.rolesAllowedUser();
	}

	@WithMockUser(roles = { "ADMIN", "USER" })
	@Test
	public void manyAnnotationsWhenMeetsConditionsThenReturnsFilteredList() throws Exception {
		List<String> names = Arrays.asList("harold", "jonathan", "pete", "bo");
		this.spring.configLocations(xml("MethodSecurityServiceEnabled")).autowire();
		List<String> filtered = this.methodSecurityService.manyAnnotations(new ArrayList<>(names));
		assertThat(filtered).hasSize(2);
		assertThat(filtered).containsExactly("harold", "jonathan");
	}

	// gh-4003
	// gh-4103
	@WithMockUser
	@Test
	public void manyAnnotationsWhenUserThenFails() {
		List<String> names = Arrays.asList("harold", "jonathan", "pete", "bo");
		this.spring.configLocations(xml("MethodSecurityServiceEnabled")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.methodSecurityService.manyAnnotations(new ArrayList<>(names)));
	}

	@WithMockUser
	@Test
	public void manyAnnotationsWhenShortListThenFails() {
		List<String> names = Arrays.asList("harold", "jonathan", "pete");
		this.spring.configLocations(xml("MethodSecurityServiceEnabled")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.methodSecurityService.manyAnnotations(new ArrayList<>(names)));
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void manyAnnotationsWhenAdminThenFails() {
		List<String> names = Arrays.asList("harold", "jonathan", "pete", "bo");
		this.spring.configLocations(xml("MethodSecurityServiceEnabled")).autowire();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.methodSecurityService.manyAnnotations(new ArrayList<>(names)));
	}

	// gh-3183
	@Test
	public void repeatedAnnotationsWhenPresentThenFails() {
		this.spring.configLocations(xml("MethodSecurityService")).autowire();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> this.methodSecurityService.repeatedAnnotations());
	}

	// gh-3183
	@Test
	public void repeatedJsr250AnnotationsWhenPresentThenFails() {
		this.spring.configLocations(xml("Jsr250")).autowire();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> this.businessService.repeatedAnnotations());
	}

	// gh-3183
	@Test
	public void repeatedSecuredAnnotationsWhenPresentThenFails() {
		this.spring.configLocations(xml("Secured")).autowire();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> this.businessService.repeatedAnnotations());
	}

	@WithMockUser
	@Test
	public void supportsMethodArgumentsInPointcut() {
		this.spring.configLocations(xml("ProtectPointcut")).autowire();
		this.businessService.someOther(0);
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.businessService.someOther("somestring"));
	}

	@Test
	public void supportsBooleanPointcutExpressions() {
		this.spring.configLocations(xml("ProtectPointcutBoolean")).autowire();
		this.businessService.someOther("somestring");
		// All others should require ROLE_USER
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(() -> this.businessService.someOther(0));
		SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")));
		this.businessService.someOther(0);
		SecurityContextHolder.clearContext();
	}

	private static String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	static class MyPermissionEvaluator implements PermissionEvaluator {

		@Override
		public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
			return "grant".equals(targetDomainObject);
		}

		@Override
		public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
				Object permission) {
			throw new UnsupportedOperationException();
		}

	}

	static class MyAuthorizationManager implements AuthorizationManager<MethodInvocation> {

		@Override
		public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation object) {
			return new AuthorizationDecision("bob".equals(authentication.get().getName()));
		}

	}

	static class MyAdvice implements MethodInterceptor {

		@Nullable
		@Override
		public Object invoke(@NotNull MethodInvocation invocation) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			if ("bob".equals(auth.getName())) {
				return "granted";
			}
			throw new AccessDeniedException("Access Denied for User '" + auth.getName() + "'");
		}

	}

}
