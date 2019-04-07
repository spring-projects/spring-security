/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.annotation;

import static org.springframework.util.StringUtils.isEmpty;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.stream.Stream;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.security.test.oauth2.annotation.WithMockJwt.WithMockJwtSecurityContextFactory;
import org.springframework.security.test.oauth2.support.JwtAuthenticationBuilder;
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
 * <li>{@link Authentication#getName() getName()} returns the JWT {@code subject} claim,
 * set from this annotation {@code name} value ({@code "user"} by default)</li>
 * <li>{@link Authentication#getAuthorities() authorities} will be a collection of
 * {@link SimpleGrantedAuthority} as defined by this annotation {@link #authorities()}
 * ({@code "ROLE_USER" } by default)</li>
 * </ul>
 *
 * Sample Usage:
 *
 * <pre>
 * &#64;WithMockJwt
 * &#64;Test
 * public void testSomethingWithDefaultJwtAuthentication() {
 *   //identified as {@code "user"} with {@code "ROLE_USER"}
 *   //claims contain {@code "sub"} (subject) with {@code "ch4mpy"} as value
 *   //headers can't be empty, so a default one is set
 *   ...
 * }
 *
 * &#64;WithMockJwt(
 *   authorities = {"ROLE_USER", "ROLE_ADMIN"},
 *   name = "ch4mpy",
 *   headers = { &#64;StringAttribute(name = "foo", value = "bar") },
 *   claims = { &#64;StringAttribute(name = "machin", value = "chose") })
 * &#64;Test
 * public void testSomethingWithCustomJwtAuthentication() {
 *   //identified as {@code "ch4mpy"} with {@code "ROLE_USER"} and {@code "ROLE_ADMIN"}
 *   //claims are {@code "machin"} with {@code "chose"} as value and {@code "sub"} (subject) with {@code "ch4mpy"} as value
 *   //single {@code "foo"} header with {@code "bar"} as value
 *   ...
 * }
 * </pre>
 *
 * @see StringAttribute
 * @see AttributeValueParser
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

	/**
	 * Alias for authorities
	 * @return Authorities the client is to be granted
	 */
	@AliasFor("authorities")
	String[] value() default { "ROLE_USER" };

	/**
	 * Alias for value
	 * @return Authorities the client is to be granted
	 */
	@AliasFor("value")
	String[] authorities() default { "ROLE_USER" };

	String[] roles() default {};

	/**
	 * @return Scopes the client is to be granted (added to "scope" claim, and authorities
	 * with "SCOPE_" prefix)
	 */
	String[] scopes() default {};

	String scopesClaimeName() default JwtAuthenticationBuilder.DEFAULT_SCOPE_ATTRIBUTE_NAME;

	/**
	 * To be used both as authentication {@code Principal} name and token {@code username}
	 * attribute.
	 * @return Resource owner name
	 */
	String name() default JwtAuthenticationBuilder.DEFAULT_AUTH_NAME;

	/**
	 * @return JWT claims
	 */
	StringAttribute[] claims() default {};

	/**
	 * Of little use at unit test time...
	 * @return JWT headers
	 */
	StringAttribute[] headers() default {
			@StringAttribute(
					name = JwtAuthenticationBuilder.DEFAULT_HEADER_NAME,
					value = JwtAuthenticationBuilder.DEFAULT_HEADER_VALUE) };

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public final class WithMockJwtSecurityContextFactory implements WithSecurityContextFactory<WithMockJwt> {
		@Override
		public SecurityContext createSecurityContext(final WithMockJwt annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(new AnnotationJwtAuthenticationBuilder(annotation).build());

			return context;
		}

		static class AnnotationJwtAuthenticationBuilder
				extends
				JwtAuthenticationBuilder<AnnotationJwtAuthenticationBuilder> {

			private final StringAttributeParserSupport parsingSupport = new StringAttributeParserSupport();

			public AnnotationJwtAuthenticationBuilder(final WithMockJwt annotation) {
				claims(parsingSupport.parse(annotation.claims()));
				scopesClaimName(nonEmptyOrNull(annotation.scopesClaimeName()));
				headers(parsingSupport.parse(annotation.headers()));
				name(nonEmptyOrNull(annotation.name()));
				Stream.of(annotation.authorities()).forEach(this::authority);
				Stream.of(annotation.roles()).forEach(this::role);
				Stream.of(annotation.scopes()).forEach(this::scope);
			}

			private static String nonEmptyOrNull(final String value) {
				return isEmpty(value) ? null : value;
			}
		}
	}
}
