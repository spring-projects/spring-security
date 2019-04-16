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
package org.springframework.security.test.context.support;

import static org.springframework.util.StringUtils.isEmpty;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Stream;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames;
import org.springframework.security.test.context.support.StringAttribute.BooleanParser;
import org.springframework.security.test.context.support.StringAttribute.DoubleParser;
import org.springframework.security.test.context.support.StringAttribute.FloatParser;
import org.springframework.security.test.context.support.StringAttribute.InstantParser;
import org.springframework.security.test.context.support.StringAttribute.IntegerParser;
import org.springframework.security.test.context.support.StringAttribute.LongParser;
import org.springframework.security.test.context.support.StringAttribute.NoOpParser;
import org.springframework.security.test.context.support.StringAttribute.SpacedSeparatedStringsParser;
import org.springframework.security.test.context.support.StringAttribute.StringListParser;
import org.springframework.security.test.context.support.StringAttribute.StringSetParser;
import org.springframework.security.test.context.support.StringAttribute.UrlParser;
import org.springframework.security.test.context.support.WithMockOidcIdToken.WithMockOidcIdTokenSecurityContextFactory;
import org.springframework.security.test.support.Defaults;
import org.springframework.security.test.support.OidcIdTokenAuthenticationBuilder;
import org.springframework.test.context.TestContext;
import org.springframework.test.web.servlet.MockMvc;

/**
 * <p>
 * A lot like {@link WithMockUser @WithMockUser} and {@link WithMockJwt @WithMockJwt}: when used with
 * {@link WithSecurityContextTestExecutionListener} this annotation can be added to a test method to emulate running
 * with a mocked OpenID authentication.
 * </p>
 * <p>
 * Main steps are:
 * </p>
 * <ul>
 * <li>{@link ClientRegistration}, {@link OAuth2AuthorizationExchange}, {@link DefaultOidcUser},
 * {@link OAuth2AccessToken} and {@link OidcIdToken} are created as per this annotation details</li>
 * <li>an {@link OAuth2LoginAuthenticationToken} is then created and fed with above objects</li>
 * <li>an empty {@link SecurityContext} is instantiated and populated with this
 * {@code OAuth2LoginAuthenticationToken}</li>
 * </ul>
 * <p>
 * As a result, the {@link Authentication} {@link MockMvc} gets from security context will has following properties:
 * </p>
 * <ul>
 * <li>{@link Authentication#getPrincipal() getPrincipal()} returns an {@link DefaultOidcUser}</li>
 * <li>{@link Authentication#getName() getName()} returns what was as defined by this annotation {@link #name()} in
 * {@link #nameAttributeKey()} claim ({@code subject} by default)</li>
 * <li>{@link Authentication#getAuthorities() getAuthorities()} will be a collection of {@link SimpleGrantedAuthority}
 * as defined by this annotation {@link #authorities()}, {@link #roles()} and {@link #scopes()}</li>
 * <li>{@link OAuth2AccessToken}, {@link ClientRegistration} and {@link OAuth2AuthorizationRequest} scopes are all the
 * same and as defined by {@link #scopes()} and {@link #authorities() authorities() prefixed with SCOPE_}
 * </ul>
 * Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockOidcIdToken
 * public void testDefaultJwtAuthentication() {
 *   //User name is "user" and authorities are [ROLE_USER]
 * }
 *
 * &#64;Test
 * &#64;WithMockOidcIdToken(name ="ch4mpy", authorities =["ROLE_USER", "SCOPE_message:read"])
 * public void testCustomNameAndAuthorities() {
 *   //User name is "ch4mpy" and authorities are [ROLE_USER, SCOPE_message:read]
 *   //Scope "message:read" is also registered as claim with default key "source"
 * }
 *
 * &#64;Test
 * &#64;WithMockOidcIdToken(scopes = "message:read", scopesClaimeName = "scp")
 * public void testCustomScopeClaim() {
 *   //User name is "user" and authorities are [SCOPE_message:read]
 *   //Scope "message:read" is also registered as claim with default key "scp"
 * }
 *
 * &#64;Test
 * &#64;WithMockOidcIdToken(claims = &#64;StringAttribute(
 *     name = "my-claim",
 *     value = "something",
 *     parser = MyAttributeValueParser.class))
 * public void testCustomScopeClaim() {
 *   //MyAttributeValueParser must implement AttributeValueParser to turn "something" into any Object
 * }
 * </pre>
 *
 * To help testing with custom claims as per last sample, many parsers are provided to parse String values:
 * <ul>
 * <li>{@link BooleanParser}</li>
 * <li>{@link DoubleParser}</li>
 * <li>{@link FloatParser}</li>
 * <li>{@link InstantParser}</li>
 * <li>{@link IntegerParser}</li>
 * <li>{@link LongParser}</li>
 * <li>{@link NoOpParser}</li>
 * <li>{@link SpacedSeparatedStringsParser}</li>
 * <li>{@link StringListParser}</li>
 * <li>{@link StringSetParser}</li>
 * <li>{@link UrlParser}</li>
 * </ul>
 *
 * @see StringAttribute
 * @see AttributeValueParser
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockOidcIdTokenSecurityContextFactory.class)
public @interface WithMockOidcIdToken {

	String tokenValue() default OidcIdTokenAuthenticationBuilder.DEFAULT_TOKEN_VALUE;

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
	 * To be used both as authentication {@code Principal} name and token {@code subscriber} (or what
	 * {@link #nameAttributeKey()} was set to) claim.
	 * @return Resource owner name
	 */
	String name() default Defaults.AUTH_NAME;

	/**
	 * @return claim name for subscriber (user name). Default value is very likely to match your need.
	 */
	String nameAttributeKey() default OidcIdTokenAuthenticationBuilder.DEFAULT_NAME_ATTRIBUTE_KEY;

	/**
	 * @return token claims
	 */
	StringAttribute[] claims() default {};

	/**
	 * @return OpenID token claims
	 */
	StringAttribute[] openIdClaims() default {};

	/**
	 * Are you sure you need to configure that ? We are building an already granted
	 * {@link OAuth2LoginAuthenticationToken}. So, unless the controller method under test (or annotation SpEL)
	 * explicitly accesses client registration, you are safe to keep defaults.
	 * @return {@link ClientRegistration} details
	 */
	MockClientRegistration clientRegistration() default @MockClientRegistration;

	/**
	 * Are you sure you need to configure that ? We are building an already granted
	 * {@link OAuth2LoginAuthenticationToken}. So, unless the controller method under test (or annotation SpEL)
	 * explicitly accesses authorization request, you are safe to keep defaults.
	 * @return {@link OAuth2AuthorizationRequest} details
	 */
	MockOAuth2AuthorizationRequest authorizationRequest() default @MockOAuth2AuthorizationRequest;

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	/**
	 * Creates a new SecurityContext containing an {@link OAuth2LoginAuthenticationToken} configured with
	 * {@link WithMockOidcIdToken @WithMockOidcIdToken}
	 *
	 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
	 * @since 5.2
	 */
	public final class WithMockOidcIdTokenSecurityContextFactory
			implements
			WithSecurityContextFactory<WithMockOidcIdToken> {

		@Override
		public SecurityContext createSecurityContext(final WithMockOidcIdToken annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(new AnnotationOidcIdTokenAuthenticationBuilder(annotation).build());

			return context;
		}

		/**
		 * Specialized {@link OidcIdTokenAuthenticationBuilder} to work with
		 * {@link WithMockOidcIdToken @WithMockOidcIdToken}
		 *
		 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
		 * @since 5.2
		 */
		static class AnnotationOidcIdTokenAuthenticationBuilder
				extends
				OidcIdTokenAuthenticationBuilder<AnnotationOidcIdTokenAuthenticationBuilder> {

			private final StringAttributeParserSupport parsingSupport = new StringAttributeParserSupport();

			public AnnotationOidcIdTokenAuthenticationBuilder(final WithMockOidcIdToken annotation) {
				super(new AuthorizationGrantType(annotation.authorizationRequest().authorizationGrantType()));
				claims(parsingSupport.parse(annotation.claims()));
				openIdClaims(parsingSupport.parse(annotation.openIdClaims()));
				tokenValue(nonEmptyOrNull(annotation.tokenValue())).name(nonEmptyOrNull(annotation.name()))
						.nameAttributeKey(nonEmptyOrNull(annotation.nameAttributeKey()));
				Stream.of(annotation.authorities()).forEach(this::authority);
				Stream.of(annotation.roles()).forEach(this::role);

				final Set<String> allScopes = getScopes(claims.get(OAuth2IntrospectionClaimNames.SCOPE), authorities);

				configureClientRegistration(annotation.clientRegistration(), allScopes);
				configureAuthorizationRequest(annotation.authorizationRequest(), allScopes);
			}

			private void configureClientRegistration(
					final MockClientRegistration annotation,
					final Collection<String> allScopes) {
				clientRegistrationBuilder.authorizationGrantType(
						isEmpty(annotation.authorizationGrantType()) ? null
								: new AuthorizationGrantType(annotation.authorizationGrantType()));
				clientRegistrationBuilder.authorizationUri(nonEmptyOrNull(annotation.authorizationUri()));
				clientRegistrationBuilder.clientAuthenticationMethod(
						isEmpty(annotation.clientAuthenticationMethod()) ? null
								: new ClientAuthenticationMethod(annotation.clientAuthenticationMethod()));
				clientRegistrationBuilder.clientId(nonEmptyOrNull(annotation.clientId()));
				clientRegistrationBuilder.clientName(nonEmptyOrNull(annotation.clientName()));
				clientRegistrationBuilder.clientSecret(nonEmptyOrNull(annotation.clientSecret()));
				clientRegistrationBuilder.jwkSetUri(nonEmptyOrNull(annotation.jwkSetUri()));
				clientRegistrationBuilder.redirectUriTemplate(nonEmptyOrNull(annotation.redirectUriTemplate()));
				clientRegistrationBuilder.providerConfigurationMetadata(
						parsingSupport.parse(annotation.providerConfigurationMetadata()));
				clientRegistrationBuilder.registrationId(nonEmptyOrNull(annotation.registrationId()));
				clientRegistrationBuilder.scope(allScopes);
				clientRegistrationBuilder.tokenUri(nonEmptyOrNull(annotation.tokenUri()));
				clientRegistrationBuilder.userInfoAuthenticationMethod(
						isEmpty(annotation.userInfoAuthenticationMethod()) ? null
								: new AuthenticationMethod(annotation.userInfoAuthenticationMethod()));
				clientRegistrationBuilder.userInfoUri(nonEmptyOrNull(annotation.userInfoUri()));
				clientRegistrationBuilder.userNameAttributeName(nonEmptyOrNull(annotation.userNameAttributeName()));
			}

			private void configureAuthorizationRequest(
					final MockOAuth2AuthorizationRequest annotation,
					final Set<String> allScopes) {
				authorizationRequestBuilder
						.authorizationRequestUri(nonEmptyOrNull(annotation.authorizationRequestUri()));
				authorizationRequestBuilder.authorizationUri(nonEmptyOrNull(annotation.authorizationUri()));
				authorizationRequestBuilder.clientId(nonEmptyOrNull(annotation.clientId()));
				authorizationRequestBuilder.redirectUri(nonEmptyOrNull(annotation.redirectUri()));
				authorizationRequestBuilder.scopes(allScopes);
			}

			private static String nonEmptyOrNull(final String value) {
				return isEmpty(value) ? null : value;
			}

		}
	}
}
