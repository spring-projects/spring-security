/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.bind.support;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.MethodParameter;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.Assert.fail;

/**
 * @author Dan Zheng
 * @since 5.2.x
 *
 */
public class CurrentSecurityContextArgumentResolverTests {
	private Object expectedPrincipal;
	private CurrentSecurityContextArgumentResolver resolver;

	@Before
	public void setup() {
		resolver = new CurrentSecurityContextArgumentResolver();
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void supportsParameterNoAnnotation() throws Exception {
		assertThat(resolver.supportsParameter(showSecurityContextNoAnnotation())).isFalse();
	}

	@Test
	public void supportsParameterAnnotation() throws Exception {
		assertThat(resolver.supportsParameter(showSecurityContextAnnotation())).isTrue();
	}

	@Test
	public void resolveArgumentNullAuthentication() throws Exception {
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		context.setAuthentication(null);
		assertThat(resolver.resolveArgument(showSecurityContextAuthenticationAnnotation(), null, null, null))
				.isNull();
		context.setAuthentication(authentication);
	}

	@Test
	public void resolveArgumentWithAuthentication() throws Exception {
		String principal = "john";
		setAuthenticationPrincipal(principal);
		Authentication auth1 = (Authentication) resolver.resolveArgument(showSecurityContextAuthenticationAnnotation(), null, null, null);
		assertThat(auth1.getPrincipal()).isEqualTo(principal);
	}

	@Test
	public void resolveArgumentWithNullAuthentication() throws Exception {
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		context.setAuthentication(null);
		assertThatExceptionOfType(SpelEvaluationException.class)
		.isThrownBy(() -> {
			resolver.resolveArgument(showSecurityContextAuthenticationWithPrincipal(), null, null, null);
		});
		context.setAuthentication(authentication);
	}

	@Test
	public void resolveArgumentWithOptionalPrincipal() throws Exception {
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		context.setAuthentication(null);
		Object principalResult = resolver.resolveArgument(showSecurityContextAuthenticationWithOptionalPrincipal(), null, null, null);
		assertThat(principalResult).isNull();
		context.setAuthentication(authentication);
	}

	@Test
	public void resolveArgumentWithPrincipal() throws Exception {
		String principal = "smith";
		setAuthenticationPrincipal(principal);
		String principalResult = (String) resolver.resolveArgument(showSecurityContextAuthenticationWithPrincipal(), null, null, null);
		assertThat(principalResult).isEqualTo(principal);
	}

	@Test
	public void resolveArgumentUserDetails() throws Exception {
		setAuthenticationDetail(new User("my_user", "my_password",
				AuthorityUtils.createAuthorityList("ROLE_USER")));

		User u = (User) resolver.resolveArgument(showSecurityContextWithUserDetail(), null, null,
				null);
		assertThat(u.getUsername()).isEqualTo("my_user");
	}

	@Test
	public void resolveArgumentSecurityContextErrorOnInvalidTypeImplicit() throws Exception {
		String principal = "invalid_type_implicit";
		setAuthenticationPrincipal(principal);
		assertThat(resolver.resolveArgument(showSecurityContextErrorOnInvalidTypeImplicit(), null, null, null))
				.isNull();
	}

	@Test
	public void resolveArgumentSecurityContextErrorOnInvalidTypeFalse() throws Exception {
		String principal = "invalid_type_false";
		setAuthenticationPrincipal(principal);
		assertThat(resolver.resolveArgument(showSecurityContextErrorOnInvalidTypeFalse(), null, null, null))
				.isNull();
	}

	@Test
	public void resolveArgumentSecurityContextErrorOnInvalidTypeTrue() throws Exception {
		String principal = "invalid_type_true";
		setAuthenticationPrincipal(principal);
		try {
			resolver.resolveArgument(showSecurityContextErrorOnInvalidTypeTrue(), null, null, null);
			fail("should not reach here");
		} catch(ClassCastException ex) {}
	}

	private MethodParameter showSecurityContextNoAnnotation() {
		return getMethodParameter("showSecurityContextNoAnnotation", String.class);
	}

	private MethodParameter showSecurityContextAnnotation() {
		return getMethodParameter("showSecurityContextAnnotation", SecurityContext.class);
	}

	private MethodParameter showSecurityContextAuthenticationAnnotation() {
		return getMethodParameter("showSecurityContextAuthenticationAnnotation", Authentication.class);
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

	private MethodParameter getMethodParameter(String methodName, Class<?>... paramTypes) {
		Method method = ReflectionUtils.findMethod(TestController.class, methodName,
				paramTypes);
		return new MethodParameter(method, 0);
	}

	public static class TestController {
		public void showSecurityContextNoAnnotation(String user) {
		}

		public void showSecurityContextAnnotation(@CurrentSecurityContext SecurityContext context) {
		}

		public void showSecurityContextAuthenticationAnnotation(@CurrentSecurityContext(expression = "authentication") Authentication authentication) {
		}

		public void showSecurityContextAuthenticationWithOptionalPrincipal(@CurrentSecurityContext(expression = "authentication?.principal") Object principal) {
		}

		public void showSecurityContextAuthenticationWithPrincipal(@CurrentSecurityContext(expression = "authentication.principal") Object principal) {
		}

		public void showSecurityContextWithUserDetail(@CurrentSecurityContext(expression = "authentication.details") Object detail) {
		}

		public void showSecurityContextErrorOnInvalidTypeImplicit(
				@CurrentSecurityContext String implicit) {
		}

		public void showSecurityContextErrorOnInvalidTypeFalse(
				@CurrentSecurityContext(errorOnInvalidType = false) String implicit) {
		}

		public void showSecurityContextErrorOnInvalidTypeTrue(
				@CurrentSecurityContext(errorOnInvalidType = true) String implicit) {
		}
	}

	private void setAuthenticationPrincipal(Object principal) {
		SecurityContextHolder.getContext()
				.setAuthentication(
						new TestingAuthenticationToken(principal, "password",
								"ROLE_USER"));
	}

	private void setAuthenticationDetail(Object detail) {
		TestingAuthenticationToken tat = new TestingAuthenticationToken("user", "password",
				"ROLE_USER");
		tat.setDetails(detail);
		SecurityContextHolder.getContext()
				.setAuthentication(tat);
	}
}
