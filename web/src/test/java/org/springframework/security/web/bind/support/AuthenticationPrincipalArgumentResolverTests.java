/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.bind.support;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.bind.annotation.AuthenticationPrincipal;
import org.springframework.util.ReflectionUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
@SuppressWarnings("deprecation")
public class AuthenticationPrincipalArgumentResolverTests {

	private Object expectedPrincipal;

	private AuthenticationPrincipalArgumentResolver resolver;

	@Before
	public void setup() {
		resolver = new AuthenticationPrincipalArgumentResolver();
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void supportsParameterNoAnnotation() {
		assertThat(resolver.supportsParameter(showUserNoAnnotation())).isFalse();
	}

	@Test
	public void supportsParameterAnnotation() {
		assertThat(resolver.supportsParameter(showUserAnnotationObject())).isTrue();
	}

	@Test
	public void supportsParameterCustomAnnotation() {
		assertThat(resolver.supportsParameter(showUserCustomAnnotation())).isTrue();
	}

	@Test
	public void resolveArgumentNullAuthentication() throws Exception {
		assertThat(resolver.resolveArgument(showUserAnnotationString(), null, null, null)).isNull();
	}

	@Test
	public void resolveArgumentNullPrincipal() throws Exception {
		setAuthenticationPrincipal(null);
		assertThat(resolver.resolveArgument(showUserAnnotationString(), null, null, null)).isNull();
	}

	@Test
	public void resolveArgumentString() throws Exception {
		setAuthenticationPrincipal("john");
		assertThat(resolver.resolveArgument(showUserAnnotationString(), null, null, null)).isEqualTo(expectedPrincipal);
	}

	@Test
	public void resolveArgumentPrincipalStringOnObject() throws Exception {
		setAuthenticationPrincipal("john");
		assertThat(resolver.resolveArgument(showUserAnnotationObject(), null, null, null)).isEqualTo(expectedPrincipal);
	}

	@Test
	public void resolveArgumentUserDetails() throws Exception {
		setAuthenticationPrincipal(new User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")));
		assertThat(resolver.resolveArgument(showUserAnnotationUserDetails(), null, null, null))
				.isEqualTo(expectedPrincipal);
	}

	@Test
	public void resolveArgumentCustomUserPrincipal() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		assertThat(resolver.resolveArgument(showUserAnnotationCustomUserPrincipal(), null, null, null))
				.isEqualTo(expectedPrincipal);
	}

	@Test
	public void resolveArgumentCustomAnnotation() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		assertThat(resolver.resolveArgument(showUserCustomAnnotation(), null, null, null)).isEqualTo(expectedPrincipal);
	}

	@Test
	public void resolveArgumentNullOnInvalidType() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		assertThat(resolver.resolveArgument(showUserAnnotationString(), null, null, null)).isNull();
	}

	@Test(expected = ClassCastException.class)
	public void resolveArgumentErrorOnInvalidType() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		resolver.resolveArgument(showUserAnnotationErrorOnInvalidType(), null, null, null);
	}

	@Test(expected = ClassCastException.class)
	public void resolveArgumentCustomserErrorOnInvalidType() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		resolver.resolveArgument(showUserAnnotationCurrentUserErrorOnInvalidType(), null, null, null);
	}

	@Test
	public void resolveArgumentObject() throws Exception {
		setAuthenticationPrincipal(new Object());
		assertThat(resolver.resolveArgument(showUserAnnotationObject(), null, null, null)).isEqualTo(expectedPrincipal);
	}

	private MethodParameter showUserNoAnnotation() {
		return getMethodParameter("showUserNoAnnotation", String.class);
	}

	private MethodParameter showUserAnnotationString() {
		return getMethodParameter("showUserAnnotation", String.class);
	}

	private MethodParameter showUserAnnotationErrorOnInvalidType() {
		return getMethodParameter("showUserAnnotationErrorOnInvalidType", String.class);
	}

	private MethodParameter showUserAnnotationCurrentUserErrorOnInvalidType() {
		return getMethodParameter("showUserAnnotationCurrentUserErrorOnInvalidType", String.class);
	}

	private MethodParameter showUserAnnotationUserDetails() {
		return getMethodParameter("showUserAnnotation", UserDetails.class);
	}

	private MethodParameter showUserAnnotationCustomUserPrincipal() {
		return getMethodParameter("showUserAnnotation", CustomUserPrincipal.class);
	}

	private MethodParameter showUserCustomAnnotation() {
		return getMethodParameter("showUserCustomAnnotation", CustomUserPrincipal.class);
	}

	private MethodParameter showUserAnnotationObject() {
		return getMethodParameter("showUserAnnotation", Object.class);
	}

	private MethodParameter getMethodParameter(String methodName, Class<?>... paramTypes) {
		Method method = ReflectionUtils.findMethod(TestController.class, methodName, paramTypes);
		return new MethodParameter(method, 0);
	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@AuthenticationPrincipal
	static @interface CurrentUser {

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@AuthenticationPrincipal(errorOnInvalidType = true)
	static @interface CurrentUserErrorOnInvalidType {

	}

	public static class TestController {

		public void showUserNoAnnotation(String user) {
		}

		public void showUserAnnotation(@AuthenticationPrincipal String user) {
		}

		public void showUserAnnotationErrorOnInvalidType(
				@AuthenticationPrincipal(errorOnInvalidType = true) String user) {
		}

		public void showUserAnnotationCurrentUserErrorOnInvalidType(@CurrentUserErrorOnInvalidType String user) {
		}

		public void showUserAnnotation(@AuthenticationPrincipal UserDetails user) {
		}

		public void showUserAnnotation(@AuthenticationPrincipal CustomUserPrincipal user) {
		}

		public void showUserCustomAnnotation(@CurrentUser CustomUserPrincipal user) {
		}

		public void showUserAnnotation(@AuthenticationPrincipal Object user) {
		}

	}

	private static class CustomUserPrincipal {

	}

	private void setAuthenticationPrincipal(Object principal) {
		this.expectedPrincipal = principal;
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken(expectedPrincipal, "password", "ROLE_USER"));
	}

}
