/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.access.expression.method;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.expression.Expression;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.annotation.sec2150.MethodInvocationFactory;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 * @since 3.0
 */
public class PrePostAnnotationSecurityMetadataSourceTests {

	private PrePostAnnotationSecurityMetadataSource mds = new PrePostAnnotationSecurityMetadataSource(
			new ExpressionBasedAnnotationAttributeFactory(new DefaultMethodSecurityExpressionHandler()));

	private MockMethodInvocation voidImpl1;

	private MockMethodInvocation voidImpl2;

	private MockMethodInvocation voidImpl3;

	private MockMethodInvocation listImpl1;

	private MockMethodInvocation notherListImpl1;

	private MockMethodInvocation notherListImpl2;

	private MockMethodInvocation annotatedAtClassLevel;

	private MockMethodInvocation annotatedAtInterfaceLevel;

	private MockMethodInvocation annotatedAtMethodLevel;

	@BeforeEach
	public void setUpData() throws Exception {
		this.voidImpl1 = new MockMethodInvocation(new ReturnVoidImpl1(), ReturnVoid.class, "doSomething", List.class);
		this.voidImpl2 = new MockMethodInvocation(new ReturnVoidImpl2(), ReturnVoid.class, "doSomething", List.class);
		this.voidImpl3 = new MockMethodInvocation(new ReturnVoidImpl3(), ReturnVoid.class, "doSomething", List.class);
		this.listImpl1 = new MockMethodInvocation(new ReturnAListImpl1(), ReturnAList.class, "doSomething", List.class);
		this.notherListImpl1 = new MockMethodInvocation(new ReturnAnotherListImpl1(), ReturnAnotherList.class,
				"doSomething", List.class);
		this.notherListImpl2 = new MockMethodInvocation(new ReturnAnotherListImpl2(), ReturnAnotherList.class,
				"doSomething", List.class);
		this.annotatedAtClassLevel = new MockMethodInvocation(new CustomAnnotationAtClassLevel(), ReturnVoid.class,
				"doSomething", List.class);
		this.annotatedAtInterfaceLevel = new MockMethodInvocation(new CustomAnnotationAtInterfaceLevel(),
				ReturnVoid2.class, "doSomething", List.class);
		this.annotatedAtMethodLevel = new MockMethodInvocation(new CustomAnnotationAtMethodLevel(), ReturnVoid.class,
				"doSomething", List.class);
	}

	@Test
	public void classLevelPreAnnotationIsPickedUpWhenNoMethodLevelExists() {
		ConfigAttribute[] attrs = this.mds.getAttributes(this.voidImpl1).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
		assertThat(attrs[0] instanceof PreInvocationExpressionAttribute).isTrue();
		PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
		assertThat(pre.getAuthorizeExpression()).isNotNull();
		assertThat(pre.getAuthorizeExpression().getExpressionString()).isEqualTo("someExpression");
		assertThat(pre.getFilterExpression()).isNull();
	}

	@Test
	public void mixedClassAndMethodPreAnnotationsAreBothIncluded() {
		ConfigAttribute[] attrs = this.mds.getAttributes(this.voidImpl2).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
		assertThat(attrs[0] instanceof PreInvocationExpressionAttribute).isTrue();
		PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
		assertThat(pre.getAuthorizeExpression().getExpressionString()).isEqualTo("someExpression");
		assertThat(pre.getFilterExpression()).isNotNull();
		assertThat(pre.getFilterExpression().getExpressionString()).isEqualTo("somePreFilterExpression");
	}

	@Test
	public void methodWithPreFilterOnlyIsAllowed() {
		ConfigAttribute[] attrs = this.mds.getAttributes(this.voidImpl3).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
		assertThat(attrs[0] instanceof PreInvocationExpressionAttribute).isTrue();
		PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
		assertThat(pre.getAuthorizeExpression().getExpressionString()).isEqualTo("permitAll");
		assertThat(pre.getFilterExpression()).isNotNull();
		assertThat(pre.getFilterExpression().getExpressionString()).isEqualTo("somePreFilterExpression");
	}

	@Test
	public void methodWithPostFilterOnlyIsAllowed() {
		ConfigAttribute[] attrs = this.mds.getAttributes(this.listImpl1).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(2);
		assertThat(attrs[0] instanceof PreInvocationExpressionAttribute).isTrue();
		assertThat(attrs[1] instanceof PostInvocationExpressionAttribute).isTrue();
		PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
		PostInvocationExpressionAttribute post = (PostInvocationExpressionAttribute) attrs[1];
		assertThat(pre.getAuthorizeExpression().getExpressionString()).isEqualTo("permitAll");
		assertThat(post.getFilterExpression()).isNotNull();
		assertThat(post.getFilterExpression().getExpressionString()).isEqualTo("somePostFilterExpression");
	}

	@Test
	public void interfaceAttributesAreIncluded() {
		ConfigAttribute[] attrs = this.mds.getAttributes(this.notherListImpl1).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
		assertThat(attrs[0] instanceof PreInvocationExpressionAttribute).isTrue();
		PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
		assertThat(pre.getFilterExpression()).isNotNull();
		assertThat(pre.getAuthorizeExpression()).isNotNull();
		assertThat(pre.getAuthorizeExpression().getExpressionString()).isEqualTo("interfaceMethodAuthzExpression");
		assertThat(pre.getFilterExpression().getExpressionString()).isEqualTo("interfacePreFilterExpression");
	}

	@Test
	public void classAttributesTakesPrecedeceOverInterfaceAttributes() {
		ConfigAttribute[] attrs = this.mds.getAttributes(this.notherListImpl2).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
		assertThat(attrs[0] instanceof PreInvocationExpressionAttribute).isTrue();
		PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
		assertThat(pre.getFilterExpression()).isNotNull();
		assertThat(pre.getAuthorizeExpression()).isNotNull();
		assertThat(pre.getAuthorizeExpression().getExpressionString()).isEqualTo("interfaceMethodAuthzExpression");
		assertThat(pre.getFilterExpression().getExpressionString()).isEqualTo("classMethodPreFilterExpression");
	}

	@Test
	public void customAnnotationAtClassLevelIsDetected() {
		ConfigAttribute[] attrs = this.mds.getAttributes(this.annotatedAtClassLevel).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
	}

	@Test
	public void customAnnotationAtInterfaceLevelIsDetected() {
		ConfigAttribute[] attrs = this.mds.getAttributes(this.annotatedAtInterfaceLevel)
			.toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
	}

	@Test
	public void customAnnotationAtMethodLevelIsDetected() {
		ConfigAttribute[] attrs = this.mds.getAttributes(this.annotatedAtMethodLevel).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
	}

	@Test
	public void proxyFactoryInterfaceAttributesFound() throws Exception {
		MockMethodInvocation mi = MethodInvocationFactory.createSec2150MethodInvocation();
		Collection<ConfigAttribute> attributes = this.mds.getAttributes(mi);
		assertThat(attributes).hasSize(1);
		Expression expression = (Expression) ReflectionTestUtils.getField(attributes.iterator().next(),
				"authorizeExpression");
		assertThat(expression.getExpressionString()).isEqualTo("hasRole('ROLE_PERSON')");
	}

	public interface ReturnVoid {

		void doSomething(List<?> param);

	}

	public interface ReturnAList {

		List<?> doSomething(List<?> param);

	}

	@PreAuthorize("interfaceAuthzExpression")
	public interface ReturnAnotherList {

		@PreAuthorize("interfaceMethodAuthzExpression")
		@PreFilter(filterTarget = "param", value = "interfacePreFilterExpression")
		List<?> doSomething(List<?> param);

	}

	@PreAuthorize("someExpression")
	public static class ReturnVoidImpl1 implements ReturnVoid {

		@Override
		public void doSomething(List<?> param) {
		}

	}

	@PreAuthorize("someExpression")
	public static class ReturnVoidImpl2 implements ReturnVoid {

		@Override
		@PreFilter(filterTarget = "param", value = "somePreFilterExpression")
		public void doSomething(List<?> param) {
		}

	}

	public static class ReturnVoidImpl3 implements ReturnVoid {

		@Override
		@PreFilter(filterTarget = "param", value = "somePreFilterExpression")
		public void doSomething(List<?> param) {
		}

	}

	public static class ReturnAListImpl1 implements ReturnAList {

		@Override
		@PostFilter("somePostFilterExpression")
		public List<?> doSomething(List<?> param) {
			return param;
		}

	}

	public static class ReturnAListImpl2 implements ReturnAList {

		@Override
		@PreAuthorize("someExpression")
		@PreFilter(filterTarget = "param", value = "somePreFilterExpression")
		@PostFilter("somePostFilterExpression")
		@PostAuthorize("somePostAuthorizeExpression")
		public List<?> doSomething(List<?> param) {
			return param;
		}

	}

	public static class ReturnAnotherListImpl1 implements ReturnAnotherList {

		@Override
		public List<?> doSomething(List<?> param) {
			return param;
		}

	}

	public static class ReturnAnotherListImpl2 implements ReturnAnotherList {

		@Override
		@PreFilter(filterTarget = "param", value = "classMethodPreFilterExpression")
		public List<?> doSomething(List<?> param) {
			return param;
		}

	}

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Inherited
	@PreAuthorize("customAnnotationExpression")
	public @interface CustomAnnotation {

	}

	@CustomAnnotation
	public interface ReturnVoid2 {

		void doSomething(List<?> param);

	}

	@CustomAnnotation
	public static class CustomAnnotationAtClassLevel implements ReturnVoid {

		@Override
		public void doSomething(List<?> param) {
		}

	}

	public static class CustomAnnotationAtInterfaceLevel implements ReturnVoid2 {

		@Override
		public void doSomething(List<?> param) {
		}

	}

	public static class CustomAnnotationAtMethodLevel implements ReturnVoid {

		@Override
		@CustomAnnotation
		public void doSomething(List<?> param) {
		}

	}

}
