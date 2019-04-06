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

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames;
import org.springframework.security.test.oauth2.annotation.StringAttribute.BooleanParser;
import org.springframework.security.test.oauth2.annotation.StringAttribute.InstantParser;
import org.springframework.security.test.oauth2.annotation.StringAttribute.StringListParser;
import org.springframework.security.test.oauth2.annotation.StringAttribute.StringSetParser;
import org.springframework.security.test.oauth2.annotation.WithMockAccessToken.WithMockAccessTokenSecurityContextFactory;
import org.springframework.security.test.oauth2.support.AbstractAuthenticationBuilder;
import org.springframework.security.test.oauth2.support.AccessTokenAuthenticationBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class WithMockAccessTokenSecurityContextFactoryTests {

	private WithMockAccessTokenSecurityContextFactory factory;

	@Before
	public void setup() {
		factory = new WithMockAccessTokenSecurityContextFactory();
	}

	@WithMockAccessToken
	private static class Default {
	}

	@WithMockAccessToken("ROLE_ADMIN")
	private static class CustomMini {
	}

	@WithMockAccessToken(
			name = "", // force null username to check fallback on subject claim
			authorities = "SCOPE_a",
			claims = {
					@StringAttribute(name = "sub", value = "ch4mpy"),
					@StringAttribute(
							name = OAuth2IntrospectionClaimNames.SCOPE,
							value = "b",
							parser = StringSetParser.class) })
	private static class SameAsResourceSreverOpaqueSampleIntegrationTests {
	}

	@WithMockAccessToken(
			name = "abracadabra",
			authorities = { "machin", "chose", "SCOPE_a", "SCOPE_b" },
			claims = {
					@StringAttribute(
							name = OAuth2IntrospectionClaimNames.ACTIVE,
							value = "false",
							parser = BooleanParser.class),
					@StringAttribute(
							name = OAuth2IntrospectionClaimNames.AUDIENCE,
							value = "c",
							parser = StringListParser.class),
					@StringAttribute(
							name = OAuth2IntrospectionClaimNames.AUDIENCE,
							value = "d",
							parser = StringListParser.class),
					@StringAttribute(name = OAuth2IntrospectionClaimNames.CLIENT_ID, value = "test-client"),
					@StringAttribute(
							name = OAuth2IntrospectionClaimNames.EXPIRES_AT,
							value = "2019-02-04T13:59:42.00Z",
							parser = InstantParser.class),
					@StringAttribute(
							name = OAuth2IntrospectionClaimNames.ISSUED_AT,
							value = "2019-02-03T13:59:42.00Z",
							parser = InstantParser.class),
					@StringAttribute(name = OAuth2IntrospectionClaimNames.ISSUER, value = "test-issuer"),
					@StringAttribute(name = OAuth2IntrospectionClaimNames.JTI, value = "test ID"),
					@StringAttribute(
							name = OAuth2IntrospectionClaimNames.NOT_BEFORE,
							value = "2019-02-03T14:00:42.00Z",
							parser = InstantParser.class),
					@StringAttribute(name = OAuth2IntrospectionClaimNames.SUBJECT, value = "test-subject") })

	private static class CustomFull {
	}

	@Test
	public void defaults() {
		final WithMockAccessToken authAnnotation =
				AnnotationUtils.findAnnotation(Default.class, WithMockAccessToken.class);
		final OAuth2IntrospectionAuthenticationToken auth =
				(OAuth2IntrospectionAuthenticationToken) factory.createSecurityContext(authAnnotation)
						.getAuthentication();
		final OAuth2AccessToken token = (OAuth2AccessToken) auth.getCredentials();
		final Map<String, Object> attributes = auth.getTokenAttributes();

		assertThat(auth.getAuthorities()).hasSize(1);
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER"))).isTrue();
		assertThat(auth.getCredentials()).isEqualTo(token);
		assertThat(auth.getDetails()).isNull();
		assertThat(auth.getName()).isEqualTo(AbstractAuthenticationBuilder.DEFAULT_AUTH_NAME);
		assertThat(auth.getPrincipal()).isInstanceOf(Map.class);

		assertThat(token.getExpiresAt()).isNull();
		assertThat(token.getIssuedAt()).isNull();
		assertThat(token.getScopes()).isEmpty();
		assertThat(token.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(token.getTokenValue()).isEqualTo(AccessTokenAuthenticationBuilder.DEFAULT_TOKEN_VALUE);

		assertThat(attributes).hasSize(2);
		assertThat(attributes.get(OAuth2IntrospectionClaimNames.TOKEN_TYPE)).isEqualTo(TokenType.BEARER);
		assertThat(attributes.get(OAuth2IntrospectionClaimNames.USERNAME))
				.isEqualTo(AbstractAuthenticationBuilder.DEFAULT_AUTH_NAME);
	}

	@Test
	public void customMini() {
		final WithMockAccessToken authAnnotation =
				AnnotationUtils.findAnnotation(CustomMini.class, WithMockAccessToken.class);
		final OAuth2IntrospectionAuthenticationToken auth =
				(OAuth2IntrospectionAuthenticationToken) factory.createSecurityContext(authAnnotation)
						.getAuthentication();
		final OAuth2AccessToken token = (OAuth2AccessToken) auth.getCredentials();
		final Map<String, Object> attributes = auth.getTokenAttributes();

		assertThat(auth.getAuthorities()).hasSize(1);
		assertThat(auth.getAuthorities()).contains(new SimpleGrantedAuthority("ROLE_ADMIN"));
		assertThat(auth.getCredentials()).isEqualTo(token);
		assertThat(auth.getDetails()).isNull();
		assertThat(auth.getName()).isEqualTo(AbstractAuthenticationBuilder.DEFAULT_AUTH_NAME);
		assertThat(auth.getPrincipal()).isInstanceOf(Map.class);

		assertThat(token.getExpiresAt()).isNull();
		assertThat(token.getIssuedAt()).isNull();
		assertThat(token.getScopes()).isEmpty();
		assertThat(token.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(token.getTokenValue()).isEqualTo(AccessTokenAuthenticationBuilder.DEFAULT_TOKEN_VALUE);

		assertThat(attributes).hasSize(2);
		assertThat(attributes.get(OAuth2IntrospectionClaimNames.TOKEN_TYPE)).isEqualTo(TokenType.BEARER);
		assertThat(attributes.get(OAuth2IntrospectionClaimNames.USERNAME))
				.isEqualTo(AbstractAuthenticationBuilder.DEFAULT_AUTH_NAME);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void scopesMixedInAuthoritiesAndClaims() {
		final WithMockAccessToken authAnnotation = AnnotationUtils
				.findAnnotation(SameAsResourceSreverOpaqueSampleIntegrationTests.class, WithMockAccessToken.class);
		final OAuth2IntrospectionAuthenticationToken auth =
				(OAuth2IntrospectionAuthenticationToken) factory.createSecurityContext(authAnnotation)
						.getAuthentication();
		final OAuth2AccessToken token = (OAuth2AccessToken) auth.getCredentials();
		final Map<String, Object> attributes = auth.getTokenAttributes();

		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(auth.getAuthorities()).contains(new SimpleGrantedAuthority("SCOPE_a"));
		assertThat(auth.getAuthorities()).contains(new SimpleGrantedAuthority("SCOPE_b"));
		assertThat(auth.getCredentials()).isEqualTo(token);
		assertThat(auth.getDetails()).isNull();
		assertThat(auth.getName()).isEqualTo("ch4mpy");
		assertThat(auth.getPrincipal()).isInstanceOf(Map.class);

		assertThat(token.getExpiresAt()).isNull();
		assertThat(token.getIssuedAt()).isNull();
		assertThat(token.getScopes()).hasSize(2);
		assertThat(token.getScopes()).contains("a");
		assertThat(token.getScopes()).contains("b");
		assertThat(token.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(token.getTokenValue()).isEqualTo(AccessTokenAuthenticationBuilder.DEFAULT_TOKEN_VALUE);

		assertThat(attributes).hasSize(3);
		assertThat(attributes.get(OAuth2IntrospectionClaimNames.TOKEN_TYPE)).isEqualTo(TokenType.BEARER);
		assertThat(attributes.get(OAuth2IntrospectionClaimNames.USERNAME)).isNull();
		assertThat((Set<String>) attributes.get(OAuth2IntrospectionClaimNames.SCOPE)).hasSize(2);
		assertThat(attributes.get("sub")).isEqualTo("ch4mpy");
	}

	@Test
	public void customFull() throws Exception {
		final WithMockAccessToken authAnnotation =
				AnnotationUtils.findAnnotation(CustomFull.class, WithMockAccessToken.class);
		final OAuth2IntrospectionAuthenticationToken auth =
				(OAuth2IntrospectionAuthenticationToken) factory.createSecurityContext(authAnnotation)
						.getAuthentication();
		final OAuth2AccessToken token = (OAuth2AccessToken) auth.getCredentials();
		final Map<String, Object> attributes = auth.getTokenAttributes();

		assertThat(auth.getAuthorities()).hasSize(4);
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("machin")));
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("chose")));
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_a")));
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_b")));

		assertThat(auth.getCredentials()).isEqualTo(token);

		assertThat(auth.getDetails()).isNull();

		assertThat(auth.getName()).isEqualTo("abracadabra");

		assertThat(auth.getPrincipal()).isEqualTo(attributes);

		assertThat(token.getExpiresAt()).isEqualTo(Instant.parse("2019-02-04T13:59:42.00Z"));
		assertThat(token.getIssuedAt()).isEqualTo(Instant.parse("2019-02-03T13:59:42.00Z"));
		assertThat(token.getScopes()).hasSize(2);
		assertThat(token.getScopes()).contains("a", "b");
		assertThat(token.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(token.getTokenValue()).isEqualTo(AccessTokenAuthenticationBuilder.DEFAULT_TOKEN_VALUE);

		assertThat(attributes).hasSize(12);
		assertThat(attributes.get(OAuth2IntrospectionClaimNames.TOKEN_TYPE)).isEqualTo(TokenType.BEARER);
		assertThat(attributes.get(OAuth2IntrospectionClaimNames.USERNAME)).isEqualTo("abracadabra");
	}

}
