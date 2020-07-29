/*
 * Copyright 2002-2015 the original author or authors.
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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.test.context.TestContext;

/**
 * When used with {@link WithSecurityContextTestExecutionListener} this annotation can be
 * added to a test method to emulate running with an anonymous user. The
 * {@link SecurityContext} that is used will contain an
 * {@link AnonymousAuthenticationToken}. This is useful when a user wants to run a
 * majority of tests as a specific user and wishes to override a few methods to be
 * anonymous. For example:
 *
 * <pre>
 * <code>
 * &#064;WithMockUser
 * public class SecurityTests {
 *     &#064;Test
 *     &#064;WithAnonymousUser
 *     public void runAsAnonymous() {
 *         // ... run as an anonymous user ...
 *     }
 *
 *     // ... lots of tests ran with a default user ...
 * }
 * </code> </pre>
 *
 * @author Rob Winch
 * @since 4.1
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithAnonymousUserSecurityContextFactory.class)
public @interface WithAnonymousUser {

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 * @since 5.1
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

}
