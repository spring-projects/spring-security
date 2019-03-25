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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Map;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.security.test.context.support.oauth2.annotations.MockClientRegistration.MockClientRegistrationSupport;
import org.springframework.security.test.context.support.oauth2.annotations.MockOAuth2AuthorizationRequest.MockOAuth2AuthorizationRequestSupport;
import org.springframework.security.test.context.support.oauth2.annotations.WithMockOidcIdToken.WithMockOidcIdTokenSecurityContextFactory;
import org.springframework.security.test.context.support.oauth2.support.OidcIdSupport;
import org.springframework.test.context.TestContext;
import org.springframework.test.web.servlet.MockMvc;

/**
 * <p>
 * A lot like
 * {@link org.springframework.security.test.context.support.WithMockUser @WithMockUser}
 * and {@link WithMockJwt @WithMockJwt}: when used with
 * {@link WithSecurityContextTestExecutionListener} this annotation can be added to a test
 * method to emulate running with a mocked OpenID authentication.
 * </p>
 * <p>
 * Main steps are:
 * </p>
 * <ul>
 * <li>{@link ClientRegistration}, {@link OAuth2AuthorizationExchange},
 * {@link DefaultOidcUser}, {@link OAuth2AccessToken} and {@link OidcIdToken} are created
 * as per this annotation details</li>
 * <li>an {@link OAuth2LoginAuthenticationToken} is then created and fed with above
 * objects</li>
 * <li>an empty {@link SecurityContext} is instantiated and populated with this
 * {@code OAuth2LoginAuthenticationToken}</li>
 * </ul>
 * <p>
 * As a result, the {@link Authentication} {@link MockMvc} gets from security context will
 * has following properties:
 * </p>
 * <ul>
 * <li>{@link Authentication#getPrincipal() getPrincipal()} returns an
 * {@link DefaultOidcUser}</li>
 * <li>{@link Authentication#getName() getName()} returns what was as defined by this
 * annotation {@link #name()} in {@link #nameAttributeKey()} claim ({@code subject} by
 * default)</li>
 * <li>{@link Authentication#getAuthorities() getAuthorities()} will be a collection of
 * {@link SimpleGrantedAuthority} as defined by this annotation
 * {@link #authorities()}</li>
 * <li>{@link OAuth2AccessToken}, {@link ClientRegistration} and
 * {@link OAuth2AuthorizationRequest} scopes are all the same and as defined by
 * {@link #scopes()}
 * </ul>
 * Sample usage:
 *
 * <pre>
 * &#64;WithMockOidcIdToken
 * &#64;Test
 * public void testSomethingWithDefaultJwtAuthentication() {
 *   ...
 * }
 *
 * &#64;WithMockOidcIdToken(
 *   authorities = {"ROLE_USER", "SOME_AUTHORITY"},
 *   name = "user",
 *   scopes = {"machin", "chose"}
 *   claims = {
 *     &#64;Attribute(name = IdTokenClaimNames.ACR, value = "bidule") })
 * &#64;Test
 * public void testSomethingWithCustomJwtAuthentication() {
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
@WithSecurityContext(factory = WithMockOidcIdTokenSecurityContextFactory.class)
public @interface WithMockOidcIdToken {

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
	 * To be used both as authentication {@code Principal} name and token
	 * {@code subscriber} (or what {@link #nameAttributeKey()} was set to) claim.
	 * @return Resource owner name
	 */
	String name() default OidcIdSupport.DEFAULT_AUTH_NAME;

	/**
	 * @return claim name for subscriber (user name). Default value is very likely to
	 * match your need.
	 */
	String nameAttributeKey() default OidcIdSupport.DEFAULT_NAME_KEY;

	/**
	 * @return token claims
	 */
	Attribute[] claims() default {};

	/**
	 * @return {@link OAuth2AccessToken} scopes (and also {@link ClientRegistration} and
	 * {@link OAuth2AuthorizationRequest})
	 */
	String[] scopes() default {};

	/**
	 * Are you sure you need to configure that ? We are building an already granted
	 * {@link OAuth2LoginAuthenticationToken}. So, unless the controller method under test
	 * (or annotation SpEL) explicitly accesses client registration, you are safe to keep
	 * defaults.
	 * @return {@link ClientRegistration} details
	 */
	MockClientRegistration clientRegistration() default @MockClientRegistration;

	/**
	 * Are you sure you need to configure that ? We are building an already granted
	 * {@link OAuth2LoginAuthenticationToken}. So, unless the controller method under test
	 * (or annotation SpEL) explicitly accesses authorization request, you are safe to
	 * keep defaults.
	 * @return {@link OAuth2AuthorizationRequest} details
	 */
	MockOAuth2AuthorizationRequest authorizationRequest() default @MockOAuth2AuthorizationRequest;

	/**
	 * Default {@link AttributeValueParser}s are provided for all {@link TargetType} but
	 * {@link TargetType#OTHER}. Providing an {@link AttributeValueParser} with same
	 * {@code SimpleName} would override it.
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

	public final class WithMockOidcIdTokenSecurityContextFactory
			implements
			WithSecurityContextFactory<WithMockOidcIdToken> {

		@Override
		public SecurityContext createSecurityContext(final WithMockOidcIdToken annotation) {
			final AttributeParsersSupport propertyParsersHelper =
					AttributeParsersSupport.withDefaultParsers(annotation.additionalParsers());

			final Map<String, Object> additionalClaims = propertyParsersHelper.parse(annotation.claims());

			final OidcIdSupport authenticationSupport =
					new OidcIdSupport(asSet(annotation.authorities()), asSet(annotation.scopes()), additionalClaims);

			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(
					authenticationSupport.authentication(
							annotation.name(),
							annotation.nameAttributeKey(),
							MockClientRegistrationSupport
									.clientRegistrationBuilder(annotation.clientRegistration(), propertyParsersHelper),
							MockOAuth2AuthorizationRequestSupport.authorizationRequestBuilder(
									annotation.authorizationRequest(),
									propertyParsersHelper)));

			return context;
		}
	}
}
