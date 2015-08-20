/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.test.context.support;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;

import org.springframework.beans.BeanUtils;
import org.springframework.core.GenericTypeResolver;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;
import org.springframework.test.context.support.AbstractTestExecutionListener;
import org.springframework.test.web.servlet.MockMvc;

/**
 * A {@link TestExecutionListener} that will find annotations that are annotated with
 * {@link WithSecurityContext} on a test method or at the class level. If found, the
 * {@link WithSecurityContext#factory()} is used to create a {@link SecurityContext} that
 * will be used with this test. If using with {@link MockMvc} the
 * {@link SecurityMockMvcRequestPostProcessors#testSecurityContext()} needs to be used
 * too.
 *
 * @author Rob Winch
 * @since 4.0
 */
public class WithSecurityContextTestExecutionListener extends
		AbstractTestExecutionListener {


	/**
	 * Sets up the {@link SecurityContext} for each test method. First the specific method
	 * is inspected for a {@link WithSecurityContext} or {@link Annotation} that has
	 * {@link WithSecurityContext} on it. If that is not found, the class is inspected. If
	 * still not found, then no {@link SecurityContext} is populated.
	 */
	@Override
	public void beforeTestMethod(TestContext testContext) throws Exception {
		SecurityContext securityContext = createSecurityContext(testContext.getTestMethod(),
				testContext);
		if (securityContext == null) {
			securityContext = createSecurityContext(testContext.getTestClass(), testContext);
		}
		if (securityContext != null) {
			TestSecurityContextHolder.setContext(securityContext);
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private SecurityContext createSecurityContext(AnnotatedElement annotated,
			TestContext context) {
		WithSecurityContext withUser = AnnotationUtils.findAnnotation(
				annotated, WithSecurityContext.class);
		if (withUser != null) {
			WithSecurityContextFactory factory = createFactory(withUser, context);
			Class<? extends Annotation> type = (Class<? extends Annotation>) GenericTypeResolver.resolveTypeArgument(factory.getClass(), WithSecurityContextFactory.class);
			Annotation annotation  = AnnotationUtils.findAnnotation(annotated, type);
			try {
				return factory.createSecurityContext(annotation);
			}
			catch (RuntimeException e) {
				throw new IllegalStateException(
						"Unable to create SecurityContext using " + annotation, e);
			}
		}
		return null;
	}

	private WithSecurityContextFactory<? extends Annotation> createFactory(
			WithSecurityContext withUser, TestContext testContext) {
		Class<? extends WithSecurityContextFactory<? extends Annotation>> clazz = withUser
				.factory();
		try {
			return testContext.getApplicationContext().getAutowireCapableBeanFactory().createBean(clazz);
		}
		catch (IllegalStateException e) {
			return BeanUtils.instantiateClass(clazz);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Clears out the {@link TestSecurityContextHolder} and the
	 * {@link SecurityContextHolder} after each test method.
	 */
	@Override
	public void afterTestMethod(TestContext testContext) throws Exception {
		TestSecurityContextHolder.clearContext();
	}

	/**
	 * Returns {@code 1000}.
	 */
	@Override
	public int getOrder() {
		return 1000;
	}
}