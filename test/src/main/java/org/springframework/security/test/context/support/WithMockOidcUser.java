/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.test.context.TestContext;
import org.springframework.test.web.servlet.MockMvc;

import java.lang.annotation.*;

/**
 * When used with {@link WithSecurityContextTestExecutionListener} this annotation can be
 * added to a test method to emulate running with a mocked user. In order to work with
 * {@link MockMvc} The {@link SecurityContext} that is used will have the following
 * properties:
 *
 * <ul>
 * <li>The Authentication that is populated in the {@link SecurityContext} is of type {@link OAuth2AuthenticationToken}.</li>
 * <li>The principal on the Authentication is Spring Security’s User object of type {@code OidcUser}.</li>
 * <li>The default User has the user name "user". You can overwrite it the name with {@link #value()} or {@link #name()}.</li>
 * <li>The default User has "ROLE_USER" and "SCOPE_openid" as {@link GrantedAuthority}.
 * You can overwrite them with {@link #scopes()} or {@link #authorities()}. </li>
 * </ul>
 *
 * @author Nena Raab
 * @see WithUserDetails
 * @since 5.4
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockOidcUserSecurityContextFactory.class)
public @interface WithMockOidcUser {

	/**
	 * Convenience mechanism for specifying the username. The default is "user". If
	 * {@link #name()} is specified it will be used instead of {@link #value()}
	 * @return
	 */
	String value() default "user";

	/**
	 * The user name or user id (subject) to be used. Note that {@link #value()} is a synonym for
	 * {@link #name()}, but if {@link #name()} is specified it will take
	 * precedence.
	 * @return
	 */
	String name() default "";

	/**
	 * <p>
	 * The scopes that should be mapped to {@code GrantedAuthority}.
	 * The default is "openid". Each value in scopes gets prefixed with "SCOPE_"
	 * and added to the list of {@link GrantedAuthority}.
	 * </p>
	 * <p>
	 * If {@link #authorities()} is specified this property cannot be changed from the default.
	 * </p>
	 *
	 * @return
	 */
	String[] scopes() default { "openid" };

	/**
	 * <p>
	 * The authorities that should be mapped to {@code GrantedAuthority}.
	 * </p>
	 *
	 * <p>
	 * If this property is specified then {@link #scopes()} is not used. This differs from
	 * {@link #scopes()} in that it does not prefix the values passed in automatically.
	 * </p>
	 * @return
	 */
	String[] authorities() default { };

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;
}
