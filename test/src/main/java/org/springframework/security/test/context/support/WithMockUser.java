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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * When used with {@link WithSecurityContextTestExecutionListener} this annotation can be
 * added to a test method to emulate running with a mocked user. In order to work with
 * {@link MockMvc} The {@link SecurityContext} that is used will have the following
 * properties:
 *
 * <ul>
 * <li>The {@link SecurityContext} created with be that of
 * {@link SecurityContextHolder#createEmptyContext()}</li>
 * <li>It will be populated with an {@link UsernamePasswordAuthenticationToken} that uses
 * the username of either {@link #value()} or {@link #username()},
 * {@link GrantedAuthority} that are specified by {@link #roles()}, and a password
 * specified by {@link #password()}.
 * </ul>
 *
 * @see WithUserDetails
 *
 * @author Rob Winch
 * @since 4.0
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockUserSecurityContextFactory.class)
public @interface WithMockUser {
	/**
	 * Convenience mechanism for specifying the username. The default is "user". If
	 * {@link #username()} is specified it will be used instead of {@link #value()}
	 * @return
	 */
	String value() default "user";

	/**
	 * The username to be used. Note that {@link #value()} is a synonym for
	 * {@link #username()}, but if {@link #username()} is specified it will take
	 * precedence.
	 * @return
	 */
	String username() default "";

	/**
	 * <p>
	 * The roles to use. The default is "USER". A {@link GrantedAuthority} will be created
	 * for each value within roles. Each value in roles will automatically be prefixed
	 * with "ROLE_". For example, the default will result in "ROLE_USER" being used.
	 * </p>
	 * <p>
	 * If {@link #authorities()} is specified this property cannot be changed from the default.
	 * </p>
	 *
	 * @return
	 */
	String[] roles() default { "USER" };

	/**
	 * <p>
	 * The authorities to use. A {@link GrantedAuthority} will be created for each value.
	 * </p>
	 *
	 * <p>
	 * If this property is specified then {@link #roles()} is not used. This differs from
	 * {@link #roles()} in that it does not prefix the values passed in automatically.
	 * </p>
	 *
	 * @return
	 */
	String[] authorities() default {};

	/**
	 * The password to be used. The default is "password".
	 * @return
	 */
	String password() default "password";
}