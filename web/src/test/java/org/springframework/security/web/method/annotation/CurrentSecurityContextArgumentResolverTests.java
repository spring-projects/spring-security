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

package org.springframework.security.web.method.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.core.MethodParameter;
import org.springframework.expression.BeanResolver;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.ReflectionUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.verify;

/**
 * @author Dan Zheng
 * @since 5.2
 *
 */
public class CurrentSecurityContextArgumentResolverTests {

	private BeanResolver beanResolver;

	private CurrentSecurityContextArgumentResolver resolver;

	@Before
	public void setup() {
		this.beanResolver = mock(BeanResolver.class);
		this.resolver = new CurrentSecurityContextArgumentResolver();
		this.resolver.setBeanResolver(this.beanResolver);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void supportsParameterNoAnnotation() {
		assertThat(this.resolver.supportsParameter(showSecurityContextNoAnnotation())).isFalse();
	}

	@Test
	public void supportsParameterAnnotation() {
		assertThat(this.resolver.supportsParameter(showSecurityContextAnnotation())).isTrue();
	}

	@Test
	public void resolveArgumentWithCustomSecurityContext() {
		String principal = "custom_security_context";
		setAuthenticationPrincipalWithCustomSecurityContext(principal);
		CustomSecurityContext customSecurityContext = (CustomSecurityContext) this.resolver
				.resolveArgument(showAnnotationWithCustomSecurityContext(), null, null, null);
		assertThat(customSecurityContext.getAuthentication().getPrincipal()).isEqualTo(principal);
	}

	@Test
	public void resolveArgumentWithCustomSecurityContextTypeMatch() {
		String principal = "custom_security_context_type_match";
		setAuthenticationPrincipalWithCustomSecurityContext(principal);
		CustomSecurityContext customSecurityContext = (CustomSecurityContext) this.resolver
				.resolveArgument(showAnnotationWithCustomSecurityContext(), null, null, null);
		assertThat(customSecurityContext.getAuthentication().getPrincipal()).isEqualTo(principal);
	}

	@Test
	public void resolveArgumentNullAuthentication() {
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		context.setAuthentication(null);
		assertThat(this.resolver.resolveArgument(showSecurityContextAuthenticationAnnotation(), null, null, null))
				.isNull();
		context.setAuthentication(authentication);
	}

	@Test
	public void resolveArgumentWithAuthentication() {
		String principal = "john";
		setAuthenticationPrincipal(principal);
		Authentication auth1 = (Authentication) this.resolver
				.resolveArgument(showSecurityContextAuthenticationAnnotation(), null, null, null);
		assertThat(auth1.getPrincipal()).isEqualTo(principal);
	}

	@Test
	public void resolveArgumentWithAuthenticationWithBean() throws Exception {
		String principal = "john";
		given(this.beanResolver.resolve(any(), eq("test"))).willReturn(principal);
		assertThat(this.resolver.resolveArgument(showSecurityContextAuthenticationWithBean(), null, null, null))
				.isEqualTo(principal);
		verify(this.beanResolver).resolve(any(), eq("test"));
	}

	@Test
	public void resolveArgumentWithNullAuthentication() {
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		context.setAuthentication(null);
		assertThatExceptionOfType(SpelEvaluationException.class).isThrownBy(() -> this.resolver
				.resolveArgument(showSecurityContextAuthenticationWithPrincipal(), null, null, null));
		context.setAuthentication(authentication);
	}

	@Test
	public void resolveArgumentWithOptionalPrincipal() {
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		context.setAuthentication(null);
		Object principalResult = this.resolver.resolveArgument(showSecurityContextAuthenticationWithOptionalPrincipal(),
				null, null, null);
		assertThat(principalResult).isNull();
		context.setAuthentication(authentication);
	}

	@Test
	public void resolveArgumentWithPrincipal() {
		String principal = "smith";
		setAuthenticationPrincipal(principal);
		String principalResult = (String) this.resolver
				.resolveArgument(showSecurityContextAuthenticationWithPrincipal(), null, null, null);
		assertThat(principalResult).isEqualTo(principal);
	}

	@Test
	public void resolveArgumentUserDetails() {
		setAuthenticationDetail(new User("my_user", "my_password", AuthorityUtils.createAuthorityList("ROLE_USER")));
		User u = (User) this.resolver.resolveArgument(showSecurityContextWithUserDetail(), null, null, null);
		assertThat(u.getUsername()).isEqualTo("my_user");
	}

	@Test
	public void resolveArgumentSecurityContextErrorOnInvalidTypeImplicit() {
		String principal = "invalid_type_implicit";
		setAuthenticationPrincipal(principal);
		assertThat(this.resolver.resolveArgument(showSecurityContextErrorOnInvalidTypeImplicit(), null, null, null))
				.isNull();
	}

	@Test
	public void resolveArgumentSecurityContextErrorOnInvalidTypeFalse() {
		String principal = "invalid_type_false";
		setAuthenticationPrincipal(principal);
		assertThat(this.resolver.resolveArgument(showSecurityContextErrorOnInvalidTypeFalse(), null, null, null))
				.isNull();
	}

	@Test
	public void resolveArgumentSecurityContextErrorOnInvalidTypeTrue() {
		String principal = "invalid_type_true";
		setAuthenticationPrincipal(principal);
		assertThatExceptionOfType(ClassCastException.class).isThrownBy(
				() -> this.resolver.resolveArgument(showSecurityContextErrorOnInvalidTypeTrue(), null, null, null));
	}

	@Test
	public void metaAnnotationWhenCurrentCustomSecurityContextThenInjectSecurityContext() {
		assertThat(this.resolver.resolveArgument(showCurrentCustomSecurityContext(), null, null, null)).isNotNull();
	}

	@Test
	public void metaAnnotationWhenCurrentAuthenticationThenInjectAuthentication() {
		String principal = "current_authentcation";
		setAuthenticationPrincipal(principal);
		Authentication auth1 = (Authentication) this.resolver.resolveArgument(showCurrentAuthentication(), null, null,
				null);
		assertThat(auth1.getPrincipal()).isEqualTo(principal);
	}

	@Test
	public void metaAnnotationWhenCurrentSecurityWithErrorOnInvalidTypeThenInjectSecurityContext() {
		assertThat(this.resolver.resolveArgument(showCurrentSecurityWithErrorOnInvalidType(), null, null, null))
				.isNotNull();
	}

	@Test
	public void metaAnnotationWhenCurrentSecurityWithErrorOnInvalidTypeThenMisMatch() {
		assertThatExceptionOfType(ClassCastException.class).isThrownBy(() -> this.resolver
				.resolveArgument(showCurrentSecurityWithErrorOnInvalidTypeMisMatch(), null, null, null));
	}

	private MethodParameter showSecurityContextNoAnnotation() {
		return getMethodParameter("showSecurityContextNoAnnotation", String.class);
	}

	private MethodParameter showSecurityContextAnnotation() {
		return getMethodParameter("showSecurityContextAnnotation", SecurityContext.class);
	}

	private MethodParameter showAnnotationWithCustomSecurityContext() {
		return getMethodParameter("showAnnotationWithCustomSecurityContext", CustomSecurityContext.class);
	}

	private MethodParameter showAnnotationWithCustomSecurityContextTypeMatch() {
		return getMethodParameter("showAnnotationWithCustomSecurityContextTypeMatch", SecurityContext.class);
	}

	private MethodParameter showSecurityContextAuthenticationAnnotation() {
		return getMethodParameter("showSecurityContextAuthenticationAnnotation", Authentication.class);
	}

	public MethodParameter showSecurityContextAuthenticationWithBean() {
		return getMethodParameter("showSecurityContextAuthenticationWithBean", String.class);
	}

	private MethodParameter showSecurityContextAuthenticationWithOptionalPrincipal() {
		return getMethodParameter("showSecurityContextAuthenticationWithOptionalPrincipal", Object.class);
	}

	private MethodParameter showSecurityContextAuthenticationWithPrincipal() {
		return getMethodParameter("showSecurityContextAuthenticationWithPrincipal", Object.class);
	}

	private MethodParameter showSecurityContextWithUserDetail() {
		return getMethodParameter("showSecurityContextWithUserDetail", Object.class);
	}

	private MethodParameter showSecurityContextErrorOnInvalidTypeImplicit() {
		return getMethodParameter("showSecurityContextErrorOnInvalidTypeImplicit", String.class);
	}

	private MethodParameter showSecurityContextErrorOnInvalidTypeFalse() {
		return getMethodParameter("showSecurityContextErrorOnInvalidTypeFalse", String.class);
	}

	private MethodParameter showSecurityContextErrorOnInvalidTypeTrue() {
		return getMethodParameter("showSecurityContextErrorOnInvalidTypeTrue", String.class);
	}

	public MethodParameter showCurrentCustomSecurityContext() {
		return getMethodParameter("showCurrentCustomSecurityContext", SecurityContext.class);
	}

	public MethodParameter showCurrentAuthentication() {
		return getMethodParameter("showCurrentAuthentication", Authentication.class);
	}

	public MethodParameter showCurrentSecurityWithErrorOnInvalidType() {
		return getMethodParameter("showCurrentSecurityWithErrorOnInvalidType", SecurityContext.class);
	}

	public MethodParameter showCurrentSecurityWithErrorOnInvalidTypeMisMatch() {
		return getMethodParameter("showCurrentSecurityWithErrorOnInvalidTypeMisMatch", String.class);
	}

	private MethodParameter getMethodParameter(String methodName, Class<?>... paramTypes) {
		Method method = ReflectionUtils.findMethod(TestController.class, methodName, paramTypes);
		return new MethodParameter(method, 0);
	}

	private void setAuthenticationPrincipal(Object principal) {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken(principal, "password", "ROLE_USER"));
	}

	private void setAuthenticationPrincipalWithCustomSecurityContext(Object principal) {
		CustomSecurityContext csc = new CustomSecurityContext();
		csc.setAuthentication(new TestingAuthenticationToken(principal, "password", "ROLE_USER"));
		SecurityContextHolder.setContext(csc);
	}

	private void setAuthenticationDetail(Object detail) {
		TestingAuthenticationToken tat = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		tat.setDetails(detail);
		SecurityContextHolder.getContext().setAuthentication(tat);
	}

	public static class TestController {

		public void showSecurityContextNoAnnotation(String user) {
		}

		public void showSecurityContextAnnotation(@CurrentSecurityContext SecurityContext context) {
		}

		public void showAnnotationWithCustomSecurityContext(@CurrentSecurityContext CustomSecurityContext context) {
		}

		public void showAnnotationWithCustomSecurityContextTypeMatch(
				@CurrentSecurityContext(errorOnInvalidType = true) SecurityContext context) {
		}

		public void showSecurityContextAuthenticationAnnotation(
				@CurrentSecurityContext(expression = "authentication") Authentication authentication) {
		}

		public void showSecurityContextAuthenticationWithBean(
				@CurrentSecurityContext(expression = "@test") String name) {
		}

		public void showSecurityContextAuthenticationWithOptionalPrincipal(
				@CurrentSecurityContext(expression = "authentication?.principal") Object principal) {
		}

		public void showSecurityContextAuthenticationWithPrincipal(
				@CurrentSecurityContext(expression = "authentication.principal") Object principal) {
		}

		public void showSecurityContextWithUserDetail(
				@CurrentSecurityContext(expression = "authentication.details") Object detail) {
		}

		public void showSecurityContextErrorOnInvalidTypeImplicit(@CurrentSecurityContext String implicit) {
		}

		public void showSecurityContextErrorOnInvalidTypeFalse(
				@CurrentSecurityContext(errorOnInvalidType = false) String implicit) {
		}

		public void showSecurityContextErrorOnInvalidTypeTrue(
				@CurrentSecurityContext(errorOnInvalidType = true) String implicit) {
		}

		public void showCurrentCustomSecurityContext(@CurrentCustomSecurityContext SecurityContext context) {
		}

		public void showCurrentAuthentication(@CurrentAuthentication Authentication authentication) {
		}

		public void showCurrentSecurityWithErrorOnInvalidType(
				@CurrentSecurityWithErrorOnInvalidType SecurityContext context) {
		}

		public void showCurrentSecurityWithErrorOnInvalidTypeMisMatch(
				@CurrentSecurityWithErrorOnInvalidType String typeMisMatch) {
		}

	}

	static class CustomSecurityContext implements SecurityContext {

		private Authentication authentication;

		@Override
		public Authentication getAuthentication() {
			return this.authentication;
		}

		@Override
		public void setAuthentication(Authentication authentication) {
			this.authentication = authentication;
		}

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@CurrentSecurityContext
	@interface CurrentCustomSecurityContext {

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@CurrentSecurityContext(expression = "authentication")
	@interface CurrentAuthentication {

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@CurrentSecurityContext(errorOnInvalidType = true)
	static @interface CurrentSecurityWithErrorOnInvalidType {

	}

}
