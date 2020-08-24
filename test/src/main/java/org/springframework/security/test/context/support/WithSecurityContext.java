/*
 * Copyright 2002-2014 the original author or authors.
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
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.test.context.TestContext;

/**
 * <p>
 * An annotation to determine what {@link SecurityContext} to use. The {@link #factory()}
 * attribute must be provided with an instance of
 * {@link WithUserDetailsSecurityContextFactory}.
 * </p>
 *
 * <p>
 * Typically this annotation will be used as an meta-annotation as done with
 * {@link WithMockUser} and {@link WithUserDetails}.
 * </p>
 *
 * <p>
 * If you would like to create your own implementation of
 * {@link WithSecurityContextFactory} you can do so by implementing the interface. You can
 * also use {@link Autowired} and other Spring semantics on the
 * {@link WithSecurityContextFactory} implementation.
 * </p>
 *
 * @author Rob Winch
 * @since 4.0
 */
@Target({ ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface WithSecurityContext {

	/**
	 * The {@link WithUserDetailsSecurityContextFactory} to use to create the
	 * {@link SecurityContext}. It can contain {@link Autowired} and other Spring
	 * annotations.
	 * @return
	 */
	Class<? extends WithSecurityContextFactory<? extends Annotation>> factory();

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 * @since 5.1
	 */
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

}
