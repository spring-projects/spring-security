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
package org.springframework.security.test.context.support;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.util.function.Supplier;

import org.springframework.beans.BeanUtils;
import org.springframework.core.GenericTypeResolver;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;
import org.springframework.test.context.support.AbstractTestExecutionListener;
import org.springframework.test.util.MetaAnnotationUtils;
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
 * @author Eddú Meléndez
 * @since 4.0
 * @see ReactorContextTestExecutionListener
 * @see org.springframework.security.test.context.annotation.SecurityTestExecutionListeners
 */
public class WithSecurityContextTestExecutionListener
		extends AbstractTestExecutionListener {

	static final String SECURITY_CONTEXT_ATTR_NAME = WithSecurityContextTestExecutionListener.class.getName().concat(".SECURITY_CONTEXT");

	/**
	 * Sets up the {@link SecurityContext} for each test method. First the specific method
	 * is inspected for a {@link WithSecurityContext} or {@link Annotation} that has
	 * {@link WithSecurityContext} on it. If that is not found, the class is inspected. If
	 * still not found, then no {@link SecurityContext} is populated.
	 */
	@Override
	public void beforeTestMethod(TestContext testContext) {
		TestSecurityContext testSecurityContext = createTestSecurityContext(
				testContext.getTestMethod(), testContext);
		if (testSecurityContext == null) {
			testSecurityContext = createTestSecurityContext(testContext.getTestClass(),
					testContext);
		}
		if (testSecurityContext == null) {
			return;
		}

		Supplier<SecurityContext> supplier = testSecurityContext
				.getSecurityContextSupplier();
		if (testSecurityContext.getTestExecutionEvent() == TestExecutionEvent.TEST_METHOD) {
			TestSecurityContextHolder.setContext(supplier.get());
		} else {
			testContext.setAttribute(SECURITY_CONTEXT_ATTR_NAME, supplier);
		}
	}

	/**
	 * If configured before test execution sets the SecurityContext
	 * @since 5.1
	 */
	@Override
	public void beforeTestExecution(TestContext testContext) {
		Supplier<SecurityContext> supplier = (Supplier<SecurityContext>) testContext
				.removeAttribute(SECURITY_CONTEXT_ATTR_NAME);
		if (supplier != null) {
			TestSecurityContextHolder.setContext(supplier.get());
		}
	}

	private TestSecurityContext createTestSecurityContext(AnnotatedElement annotated,
			TestContext context) {
		WithSecurityContext withSecurityContext = AnnotatedElementUtils
				.findMergedAnnotation(annotated, WithSecurityContext.class);
		return createTestSecurityContext(annotated, withSecurityContext, context);
	}

	private TestSecurityContext createTestSecurityContext(Class<?> annotated,
			TestContext context) {
		MetaAnnotationUtils.AnnotationDescriptor<WithSecurityContext> withSecurityContextDescriptor = MetaAnnotationUtils
				.findAnnotationDescriptor(annotated, WithSecurityContext.class);
		WithSecurityContext withSecurityContext = withSecurityContextDescriptor == null
				? null : withSecurityContextDescriptor.getAnnotation();
		return createTestSecurityContext(annotated, withSecurityContext, context);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private TestSecurityContext createTestSecurityContext(AnnotatedElement annotated,
			WithSecurityContext withSecurityContext, TestContext context) {
		if (withSecurityContext == null) {
			return null;
		}
		withSecurityContext = AnnotationUtils
			.synthesizeAnnotation(withSecurityContext, annotated);
		WithSecurityContextFactory factory = createFactory(withSecurityContext, context);
		Class<? extends Annotation> type = (Class<? extends Annotation>) GenericTypeResolver
				.resolveTypeArgument(factory.getClass(),
						WithSecurityContextFactory.class);
		Annotation annotation = findAnnotation(annotated, type);
		Supplier<SecurityContext> supplier = () -> {
			try {
				return factory.createSecurityContext(annotation);
			} catch (RuntimeException e) {
				throw new IllegalStateException(
						"Unable to create SecurityContext using " + annotation, e);
			}
		};
		TestExecutionEvent initialize = withSecurityContext.setupBefore();
		return new TestSecurityContext(supplier, initialize);
	}

	private Annotation findAnnotation(AnnotatedElement annotated,
			Class<? extends Annotation> type) {
		Annotation findAnnotation = AnnotationUtils.findAnnotation(annotated, type);
		if (findAnnotation != null) {
			return findAnnotation;
		}
		Annotation[] allAnnotations = AnnotationUtils.getAnnotations(annotated);
		for (Annotation annotationToTest : allAnnotations) {
			WithSecurityContext withSecurityContext = AnnotationUtils.findAnnotation(
					annotationToTest.annotationType(), WithSecurityContext.class);
			if (withSecurityContext != null) {
				return annotationToTest;
			}
		}
		return null;
	}

	private WithSecurityContextFactory<? extends Annotation> createFactory(
			WithSecurityContext withSecurityContext, TestContext testContext) {
		Class<? extends WithSecurityContextFactory<? extends Annotation>> clazz = withSecurityContext
				.factory();
		try {
			return testContext.getApplicationContext().getAutowireCapableBeanFactory()
					.createBean(clazz);
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
	public void afterTestMethod(TestContext testContext) {
		TestSecurityContextHolder.clearContext();
	}

	/**
	 * Returns {@code 10000}.
	 */
	@Override
	public int getOrder() {
		return 10000;
	}

	static class TestSecurityContext {
		private final Supplier<SecurityContext> securityContextSupplier;
		private final TestExecutionEvent testExecutionEvent;

		TestSecurityContext(Supplier<SecurityContext> securityContextSupplier,
				TestExecutionEvent testExecutionEvent) {
			this.securityContextSupplier = securityContextSupplier;
			this.testExecutionEvent = testExecutionEvent;
		}

		public Supplier<SecurityContext> getSecurityContextSupplier() {
			return this.securityContextSupplier;
		}

		public TestExecutionEvent getTestExecutionEvent() {
			return this.testExecutionEvent;
		}
	}
}
