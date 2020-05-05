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
import org.springframework.security.test.context.support.*;
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
 * <li>The default User has the username of "user", {@link #value()} or {@link #name()} and does not have to exist.</li>
 * <li>The default User has and a single GrantedAuthority {@link GrantedAuthority} or those that are specified by {@link #authorities()}.</li>
 * </ul>
 *
 * @author Nena Raab
 * @see WithUserDetails
 * @since 5.3
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
	 *
	 * @return
	 */
	String value() default "user";

	/**
	 * The user name oder user id (subject) to be used. Note that {@link #value()} is a synonym for
	 * {@link #name()}, but if {@link #name()} is specified it will take
	 * precedence.
	 *
	 * @return
	 */
	String name() default "";

	/**
	 * <p>
	 * The authorities to use. The default is "openid". A {@link GrantedAuthority} will be created for each value.
	 * </p>
	 * *
	 *
	 * @return
	 */
	String[] authorities() default { "openid" };

	/**
	 * The name of the OIDC token claim that contains the subject identifier that identifies the End-User.
	 * The default is "sub".
	 *
	 * @return
	 */
	String nameTokenClaim() default "sub";

	/**
	 * The password to be used. The default is "clientId".
	 *
	 * @return
	 */
	String clientId() default "clientId";

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 *
	 * @return the {@link TestExecutionEvent} to initialize before
	 * @since 5.1
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;
}
