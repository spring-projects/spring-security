/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.context.support.oauth2;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.security.test.context.support.oauth2.properties.Property;
import org.springframework.security.test.context.support.oauth2.properties.PropertyParser;
import org.springframework.security.test.context.support.oauth2.properties.PropertyParsersHelper;
import org.springframework.test.context.TestContext;
import org.springframework.test.web.servlet.MockMvc;

/**
 * <p>
 * A lot like
 * {@link org.springframework.security.test.context.support.WithMockUser @WithMockUser}:
 * when used with {@link WithSecurityContextTestExecutionListener} this annotation can be
 * added to a test method to emulate running with a mocked authentication created out of a
 * {@link Jwt JWT}.
 * </p>
 * <p>
 * Main steps are:
 * </p>
 * <ul>
 * <li>A {@link Jwt JWT} is created as per this annotation {@code name} (forces
 * {@code subject} claim), {@code headers} and {@code claims}</li>
 * <li>A {@link JwtAuthenticationToken JwtAuthenticationToken} is then created and fed
 * with this new JWT token</li>
 * <li>An empty {@link SecurityContext} is instantiated and populated with this
 * {@code JwtAuthenticationToken}</li>
 * </ul>
 * <p>
 * As a result, the {@link Authentication} {@link MockMvc} gets from security context will
 * have the following properties:
 * </p>
 * <ul>
 * <li>{@link Authentication#getPrincipal() getPrincipal()} returns a {@link Jwt}</li>
 * <li>{@link Authentication#getName() getName()} returns the JWT {@code subject} claim
 * (set from this annotation {@code name} value)</li>
 * <li>{@link Authentication#getAuthorities() authorities} will be a collection of
 * {@link SimpleGrantedAuthority} as defined by this annotation {@code authorities}</li>
 * </ul>
 *
 * Sample Usage:
 *
 * <pre>
 * &#64;WithMockJwt
 * &#64;Test
 * public void testSomethingWithDefaultJwtAuthentication() {
 *   //no authority
 *   //single {@link DEFAULT_HEADER_NAME} header (can't be empty)
 *   //"sub" claim (subject) with {@link DEFAULT_AUTH_NAME} as value
 *   ...
 * }
 *
 * &#64;WithMockJwt(
 *   authorities = {"ROLE_USER", "ROLE_ADMIN"},
 *   name = "user",
 *   headers = { &#64;Property(name = "foo", value = "bar") },
 *   claims = { &#64;Property(name = "machin", value = "chose") })
 * &#64;Test
 * public void testSomethingWithCustomJwtAuthentication() {
 *   //two authorities
 *   //single "foo" header with "bar" as value
 *   //"machin" claim with "chose" as value
 *   //"sub" claim (subject) with "user" as value
 *   ...
 * }
 * </pre>
 *
 * @see Property
 * @see PropertyParser
 * @see PropertyParsersHelper#DEFAULT_PARSERS
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockJwtSecurityContextFactory.class)
public @interface WithMockJwt {
	public static final String DEFAULT_AUTH_NAME = "user";
	public static final String DEFAULT_HEADER_NAME = "alg";
	public static final String DEFAULT_HEADER_VALUE = "test-algorythm";

	/**
	 * Alias for authorities
	 * @return Authorities the client is to be granted
	 */
	@AliasFor("authorities")
	String[] value() default {};

	/**
	 * Alias for value
	 * @return Authorities the client is to be granted
	 */
	@AliasFor("value")
	String[] authorities() default {};

	/**
	 * To be used both as authentication {@code Principal} name and token {@code username}
	 * attribute.
	 * @return Resource owner name
	 */
	String name() default DEFAULT_AUTH_NAME;

	/**
	 * @return JWT claims
	 */
	Property[] claims() default {};

	/**
	 * Of little use at unit test time...
	 * @return JWT headers
	 */
	Property[] headers() default {
			@Property(name = DEFAULT_HEADER_NAME, value = DEFAULT_HEADER_VALUE) };

	/**
	 * {@link PropertyParsersHelper#DEFAULT_PARSERS Defaulted parsers} are provided for
	 * most common value types.
	 *
	 * @return parsers to add to default ones (or override)
	 *
	 * @see PropertyParsersHelper#DEFAULT_PARSERS
	 */
	String[] additionalParsers() default {};

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;
}
