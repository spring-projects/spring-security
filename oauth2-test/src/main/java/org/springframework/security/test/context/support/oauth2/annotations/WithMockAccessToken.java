/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.context.support.oauth2.annotations;

import static org.springframework.security.test.context.support.oauth2.support.CollectionsSupport.asSet;
import static org.springframework.security.test.context.support.oauth2.annotations.AttributeParsersSupport.withDefaultParsers;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.Map;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.security.test.context.support.oauth2.annotations.WithMockAccessToken.WithMockAccessTokenSecurityContextFactory;
import org.springframework.security.test.context.support.oauth2.support.AccessTokenSupport;
import org.springframework.test.context.TestContext;
import org.springframework.test.web.servlet.MockMvc;

/**
 * <p>
 * A lot like {@link org.springframework.security.test.context.support.WithMockUser @WithMockUser} and
 * {@link WithMockJwt @WithMockJwt}: when used with {@link WithSecurityContextTestExecutionListener} this annotation can
 * be added to a test method to emulate running with a mocked authentication created out of a Bearer token.
 * </p>
 * <p>
 * Main steps are:
 * </p>
 * <ul>
 * <li>A Bearer token ({@link OAuth2AccessToken}) is created as per this annotation {@link #name()} (forces
 * {@code username} claim) and {@link #claims()}</li>
 * <li>A {@link OAuth2IntrospectionAuthenticationToken} is then created and fed with this new token</li>
 * <li>An empty {@link SecurityContext} is instantiated and populated with this
 * {@link OAuth2IntrospectionAuthenticationToken}</li>
 * </ul>
 * <p>
 * As a result, the {@link Authentication} {@link MockMvc} gets from security context will have the following
 * properties:
 * </p>
 * <ul>
 * <li>{@link Authentication#getPrincipal() getPrincipal()} returns an {@link OAuth2AccessToken}</li>
 * <li>{@link Authentication#getName() getName()} returns what was as defined by this annotation {@link #name()}
 * ({@code "user"} by default)</li>
 * <li>{@link Authentication#getAuthorities() getAuthorities()} will be a collection of {@link SimpleGrantedAuthority}
 * as defined by this annotation {@link #authorities()} ({@code "ROLE_USER"} by default)</li>
 * <li>token {@code token_type} claim is always present and forced to {@link TokenType#BEARER Bearer}</li>
 * <li>token {@code username} claim is always present and forced to the value of this annotation {@link #name()}
 * property</li>
 * </ul>
 * Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockAccessToken
 * public void testSomethingWithDefaultJwtAuthentication() {
 *   //authenticated as "user" with "ROLE_USER"
 *   //authentication "token_type" attribute is TokenType.BEARER
 *   //authentication "username" attribute is "user"
 *   ...
 * }
 *
 * &#64;Test
 * &#64;WithMockAccessToken(
 *   authorities = {"ROLE_USER", "SOME_AUTHORITY"},
 *   name = "ch4mpy",
 *   claims = {
 *     &#64;Attribute(name = OAuth2IntrospectionClaimNames.SCOPE, value = "truc", parseTo = TargetType.STRING_SET),
 *     &#64;Attribute(name = OAuth2IntrospectionClaimNames.SCOPE, value = "chose", parseTo = TargetType.STRING_SET) })
 * public void testSomethingWithCustomJwtAuthentication() {
 *   //authenticated as "ch4mpy" with "ROLE_USER" and "SOME_AUTHORITY"
 *   //both authentication "scope" attribute and  token scopes are { "chose", "truc" }
 *   //authentication "token_type" attribute is TokenType.BEARER
 *   //authentication "username" attribute is "ch4mpy"
 *   ...
 * }
 * </pre>
 *
 * @see Attribute
 * @see AttributeValueParser
 * @see TargetType
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockAccessTokenSecurityContextFactory.class)
public @interface WithMockAccessToken {
	public static final String DEFAULT_AUTH_NAME = "user";

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

	/**
	 * Alias for value
	 * @return Scopes the client is to be granted (to be added to "scope" attribute, and authorities with "SCOPE_"
	 * prefix)
	 */
	String[] scopes() default {};

	/**
	 * To be used both as authentication {@code Principal} name and token {@code username} attribute.
	 * @return Resource owner name
	 */
	String name() default DEFAULT_AUTH_NAME;

	/**
	 * @return Bearer token description
	 */
	Attribute[] claims() default {};

	/**
	 * {@link AttributeValueParser}s are provided for all {@link TargetType} but {@link TargetType#OTHER}. Providing a
	 * parser with same {@code SimpleName} as default one will override it
	 *
	 * @return parsers to add to default ones (or override)
	 *
	 * @see TargetType
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

	public final class WithMockAccessTokenSecurityContextFactory
			implements
			WithSecurityContextFactory<WithMockAccessToken> {
		public static final String DEFAULT_TOKEN_VALUE = "Bearer test";

		@Override
		public SecurityContext createSecurityContext(final WithMockAccessToken annotation) {
			final Map<String, Object> attributes =
					new HashMap<>(withDefaultParsers(annotation.additionalParsers()).parse(annotation.claims()));
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(
					AccessTokenSupport.authentication(
							annotation.name(),
							asSet(annotation.authorities()),
							asSet(annotation.scopes()),
							attributes));
			return context;
		}
	}
}
