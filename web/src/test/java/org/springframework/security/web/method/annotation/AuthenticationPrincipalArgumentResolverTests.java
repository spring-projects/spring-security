/*
 * Copyright 2002-2024 the original author or authors.
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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.annotation.AnnotatedMethod;
import org.springframework.expression.BeanResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.ReflectionUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.verify;

/**
 * @author Rob Winch
 *
 */
public class AuthenticationPrincipalArgumentResolverTests {

	private BeanResolver beanResolver;

	private Object expectedPrincipal;

	private AuthenticationPrincipalArgumentResolver resolver;

	@BeforeEach
	public void setup() {
		this.beanResolver = mock(BeanResolver.class);
		this.resolver = new AuthenticationPrincipalArgumentResolver();
		this.resolver.setBeanResolver(this.beanResolver);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void supportsParameterNoAnnotation() {
		assertThat(this.resolver.supportsParameter(showUserNoAnnotation())).isFalse();
	}

	@Test
	public void supportsParameterAnnotation() {
		assertThat(this.resolver.supportsParameter(showUserAnnotationObject())).isTrue();
	}

	@Test
	public void supportsParameterCustomAnnotation() {
		assertThat(this.resolver.supportsParameter(showUserCustomAnnotation())).isTrue();
	}

	@Test
	public void resolveArgumentNullAuthentication() throws Exception {
		assertThat(this.resolver.resolveArgument(showUserAnnotationString(), null, null, null)).isNull();
	}

	@Test
	public void resolveArgumentNullPrincipal() throws Exception {
		setAuthenticationPrincipal(null);
		assertThat(this.resolver.resolveArgument(showUserAnnotationString(), null, null, null)).isNull();
	}

	@Test
	public void resolveArgumentString() throws Exception {
		setAuthenticationPrincipal("john");
		assertThat(this.resolver.resolveArgument(showUserAnnotationString(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentPrincipalStringOnObject() throws Exception {
		setAuthenticationPrincipal("john");
		assertThat(this.resolver.resolveArgument(showUserAnnotationObject(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentUserDetails() throws Exception {
		setAuthenticationPrincipal(new User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")));
		assertThat(this.resolver.resolveArgument(showUserAnnotationUserDetails(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentCustomUserPrincipal() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		assertThat(this.resolver.resolveArgument(showUserAnnotationCustomUserPrincipal(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentCustomAnnotation() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		assertThat(this.resolver.resolveArgument(showUserCustomAnnotation(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentSpel() throws Exception {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		setAuthenticationPrincipal(principal);
		this.expectedPrincipal = principal.property;
		assertThat(this.resolver.resolveArgument(showUserSpel(), null, null, null)).isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentSpelBean() throws Exception {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		setAuthenticationPrincipal(principal);
		given(this.beanResolver.resolve(any(), eq("test"))).willReturn(principal.property);
		this.expectedPrincipal = principal.property;
		assertThat(this.resolver.resolveArgument(showUserSpelBean(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
		verify(this.beanResolver).resolve(any(), eq("test"));
	}

	@Test
	public void resolveArgumentSpelCopy() throws Exception {
		CopyUserPrincipal principal = new CopyUserPrincipal("property");
		setAuthenticationPrincipal(principal);
		Object resolveArgument = this.resolver.resolveArgument(showUserSpelCopy(), null, null, null);
		assertThat(resolveArgument).isEqualTo(principal);
		assertThat(resolveArgument).isNotSameAs(principal);
	}

	@Test
	public void resolveArgumentSpelPrimitive() throws Exception {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		setAuthenticationPrincipal(principal);
		this.expectedPrincipal = principal.id;
		assertThat(this.resolver.resolveArgument(showUserSpelPrimitive(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentNullOnInvalidType() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		assertThat(this.resolver.resolveArgument(showUserAnnotationString(), null, null, null)).isNull();
	}

	@Test
	public void resolveArgumentErrorOnInvalidType() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		assertThatExceptionOfType(ClassCastException.class)
			.isThrownBy(() -> this.resolver.resolveArgument(showUserAnnotationErrorOnInvalidType(), null, null, null));
	}

	@Test
	public void resolveArgumentCustomserErrorOnInvalidType() throws Exception {
		setAuthenticationPrincipal(new CustomUserPrincipal());
		assertThatExceptionOfType(ClassCastException.class).isThrownBy(() -> this.resolver
			.resolveArgument(showUserAnnotationCurrentUserErrorOnInvalidType(), null, null, null));
	}

	@Test
	public void resolveArgumentObject() throws Exception {
		setAuthenticationPrincipal(new Object());
		assertThat(this.resolver.resolveArgument(showUserAnnotationObject(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentCustomMetaAnnotation() throws Exception {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		setAuthenticationPrincipal(principal);
		this.expectedPrincipal = principal.id;
		assertThat(this.resolver.resolveArgument(showUserCustomMetaAnnotation(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentCustomMetaAnnotationTpl() throws Exception {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		setAuthenticationPrincipal(principal);
		this.resolver.setTemplateDefaults(new AnnotationTemplateExpressionDefaults());
		this.expectedPrincipal = principal.id;
		assertThat(this.resolver.resolveArgument(showUserCustomMetaAnnotationTpl(), null, null, null))
			.isEqualTo(this.expectedPrincipal);
	}

	@Test
	public void resolveArgumentWhenAliasForOnInterfaceThenInherits() throws Exception {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		setAuthenticationPrincipal(principal);
		assertThat(this.resolver.resolveArgument(showUserNoConcreteAnnotation(), null, null, null))
			.isEqualTo(principal.property);
	}

	private MethodParameter showUserNoAnnotation() {
		return getMethodParameter("showUserNoAnnotation", String.class);
	}

	private MethodParameter showUserNoConcreteAnnotation() {
		return getMethodParameter("showUserNoConcreteAnnotation", String.class);
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

	private MethodParameter showUserSpel() {
		return getMethodParameter("showUserSpel", String.class);
	}

	private MethodParameter showUserSpelBean() {
		return getMethodParameter("showUserSpelBean", String.class);
	}

	private MethodParameter showUserSpelCopy() {
		return getMethodParameter("showUserSpelCopy", CopyUserPrincipal.class);
	}

	private MethodParameter showUserSpelPrimitive() {
		return getMethodParameter("showUserSpelPrimitive", int.class);
	}

	private MethodParameter showUserAnnotationObject() {
		return getMethodParameter("showUserAnnotation", Object.class);
	}

	private MethodParameter showUserCustomMetaAnnotation() {
		return getMethodParameter("showUserCustomMetaAnnotation", int.class);
	}

	private MethodParameter showUserCustomMetaAnnotationTpl() {
		return getMethodParameter("showUserCustomMetaAnnotationTpl", int.class);
	}

	private MethodParameter getMethodParameter(String methodName, Class<?>... paramTypes) {
		Method method = ReflectionUtils.findMethod(TestController.class, methodName, paramTypes);
		return new AnnotatedMethod(method).getMethodParameters()[0];
	}

	private void setAuthenticationPrincipal(Object principal) {
		this.expectedPrincipal = principal;
		SecurityContextHolder.getContext()
			.setAuthentication(new TestingAuthenticationToken(this.expectedPrincipal, "password", "ROLE_USER"));
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

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@AuthenticationPrincipal
	@interface Property {

		@AliasFor(attribute = "expression", annotation = AuthenticationPrincipal.class)
		String value() default "id";

	}

	@Retention(RetentionPolicy.RUNTIME)
	@AuthenticationPrincipal
	public @interface CurrentUser2 {

		@AliasFor(annotation = AuthenticationPrincipal.class)
		String expression() default "";

	}

	@Retention(RetentionPolicy.RUNTIME)
	@AuthenticationPrincipal(expression = "principal.{property}")
	public @interface CurrentUser3 {

		String property() default "";

	}

	public interface TestInterface {

		void showUserNoConcreteAnnotation(@Property("property") String property);

	}

	public static class TestController implements TestInterface {

		public void showUserNoAnnotation(String user) {
		}

		@Override
		public void showUserNoConcreteAnnotation(String user) {

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

		public void showUserCustomMetaAnnotation(@CurrentUser2(expression = "principal.id") int userId) {
		}

		public void showUserCustomMetaAnnotationTpl(@CurrentUser3(property = "id") int userId) {
		}

		public void showUserAnnotation(@AuthenticationPrincipal Object user) {
		}

		public void showUserSpel(@AuthenticationPrincipal(expression = "property") String user) {
		}

		public void showUserSpelBean(@AuthenticationPrincipal(expression = "@test") String user) {
		}

		public void showUserSpelCopy(@AuthenticationPrincipal(
				expression = "new org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolverTests$CopyUserPrincipal(#this)") CopyUserPrincipal user) {
		}

		public void showUserSpelPrimitive(@AuthenticationPrincipal(expression = "id") int id) {
		}

	}

	static class CustomUserPrincipal {

		public final String property = "property";

		public final int id = 1;

		public Object getPrincipal() {
			return this;
		}

	}

	public static class CopyUserPrincipal {

		public final String property;

		public CopyUserPrincipal(String property) {
			this.property = property;
		}

		public CopyUserPrincipal(CopyUserPrincipal toCopy) {
			this.property = toCopy.property;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			CopyUserPrincipal other = (CopyUserPrincipal) obj;
			if (this.property == null) {
				if (other.property != null) {
					return false;
				}
			}
			else if (!this.property.equals(other.property)) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((this.property == null) ? 0 : this.property.hashCode());
			return result;
		}

	}

}
