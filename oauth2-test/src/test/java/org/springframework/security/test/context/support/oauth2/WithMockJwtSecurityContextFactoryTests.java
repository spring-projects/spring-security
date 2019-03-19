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
package org.springframework.security.test.context.support.oauth2;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URL;
import java.time.Instant;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.oauth2.attributes.Attribute;
import org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelper.TargetType;
import org.springframework.security.test.context.support.oauth2.attributes.AttributeValueParser;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
public class WithMockJwtSecurityContextFactoryTests {

	private WithMockJwtSecurityContextFactory factory;

	@Before
	public void setup() {
		factory = new WithMockJwtSecurityContextFactory();
	}

	@WithMockJwt
	private static class Default {
	}

	@WithMockJwt("ROLE_ADMIN")
	private static class CustomMini {
	}

	@WithMockJwt(name = "Test User", authorities = { "ROLE_USER", "ROLE_ADMIN" })
	private static class CustomFrequent {
	}

	@WithMockJwt(
			name = "Test User",
			authorities = { "ROLE_USER", "ROLE_ADMIN" },
			claims = { @Attribute(name = "custom-claim", value = "foo") })
	private static class CustomAdvanced {
	}

	@WithMockJwt(
			name = "truc",
			authorities = { "machin", "chose" },
			headers = { @Attribute(name = "a", value = "1") },
			claims = {
					@Attribute(name = JwtClaimNames.AUD, value = "test audience", parseTo = TargetType.STRING_LIST),
					@Attribute(name = JwtClaimNames.AUD, value = "other audience", parseTo = TargetType.STRING_LIST),
					@Attribute(name = JwtClaimNames.ISS, value = "https://test-issuer.org", parseTo = TargetType.URL),
					@Attribute(
							name = JwtClaimNames.IAT,
							value = "2019-03-03T22:35:00.0Z",
							parseTo = TargetType.INSTANT),
					@Attribute(name = JwtClaimNames.JTI, value = "test ID"),
					@Attribute(name = "custom-claim", value = "foo") },
			additionalParsers = {
					"org.springframework.security.test.context.support.oauth2.WithMockJwtSecurityContextFactoryTests$FooParser" })
	private static class CustomFull {
	}

	@Test
	public void defaults() {
		final WithMockJwt annotation = AnnotationUtils.findAnnotation(Default.class, WithMockJwt.class);

		final Authentication auth = factory.createSecurityContext(annotation).getAuthentication();

		assertThat(auth.getName()).isEqualTo(WithMockJwt.DEFAULT_AUTH_NAME);
		assertThat(auth.getAuthorities()).hasSize(1);
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER"))).isTrue();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue()).isEqualTo(WithMockJwtSecurityContextFactory.DEFAULT_TOKEN_VALUE);
		assertThat(jwt.getSubject()).isEqualTo(WithMockJwt.DEFAULT_AUTH_NAME);
		assertThat(jwt.getAudience()).isNull();
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getIssuedAt()).isNull();
		assertThat(jwt.getExpiresAt()).isNull();
		assertThat(jwt.getNotBefore()).isNull();
		assertThat(jwt.getId()).isNull();

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(WithMockJwt.DEFAULT_HEADER_NAME)).isEqualTo(WithMockJwt.DEFAULT_HEADER_VALUE);
	}

	@Test
	public void customMini() {
		final WithMockJwt annotation = AnnotationUtils.findAnnotation(CustomMini.class, WithMockJwt.class);

		final Authentication auth = factory.createSecurityContext(annotation).getAuthentication();

		assertThat(auth.getName()).isEqualTo(WithMockJwt.DEFAULT_AUTH_NAME);
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"))).isTrue();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue()).isEqualTo(WithMockJwtSecurityContextFactory.DEFAULT_TOKEN_VALUE);
		assertThat(jwt.getSubject()).isEqualTo(WithMockJwt.DEFAULT_AUTH_NAME);
		assertThat(jwt.getAudience()).isNull();
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getIssuedAt()).isNull();
		assertThat(jwt.getExpiresAt()).isNull();
		assertThat(jwt.getNotBefore()).isNull();
		assertThat(jwt.getId()).isNull();

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(WithMockJwt.DEFAULT_HEADER_NAME)).isEqualTo(WithMockJwt.DEFAULT_HEADER_VALUE);
	}

	@Test
	public void customFrequent() {
		final WithMockJwt annotation = AnnotationUtils.findAnnotation(CustomFrequent.class, WithMockJwt.class);

		final Authentication auth = factory.createSecurityContext(annotation).getAuthentication();

		assertThat(auth.getName()).isEqualTo("Test User");
		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(
				auth.getAuthorities()
						.stream()
						.allMatch(
								a -> a.equals(new SimpleGrantedAuthority("ROLE_ADMIN"))
										|| a.equals(new SimpleGrantedAuthority("ROLE_USER")))).isTrue();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue()).isEqualTo(WithMockJwtSecurityContextFactory.DEFAULT_TOKEN_VALUE);
		assertThat(jwt.getSubject()).isEqualTo("Test User");
		assertThat(jwt.getAudience()).isNull();
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getIssuedAt()).isNull();
		assertThat(jwt.getExpiresAt()).isNull();
		assertThat(jwt.getNotBefore()).isNull();
		assertThat(jwt.getId()).isNull();

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(WithMockJwt.DEFAULT_HEADER_NAME)).isEqualTo(WithMockJwt.DEFAULT_HEADER_VALUE);
	}

	@Test
	public void customAdvanced() {
		final WithMockJwt annotation = AnnotationUtils.findAnnotation(CustomAdvanced.class, WithMockJwt.class);

		final Authentication auth = factory.createSecurityContext(annotation).getAuthentication();

		assertThat(auth.getName()).isEqualTo("Test User");
		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(
				auth.getAuthorities()
						.stream()
						.allMatch(
								a -> a.equals(new SimpleGrantedAuthority("ROLE_ADMIN"))
										|| a.equals(new SimpleGrantedAuthority("ROLE_USER")))).isTrue();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue()).isEqualTo(WithMockJwtSecurityContextFactory.DEFAULT_TOKEN_VALUE);
		assertThat(jwt.getSubject()).isEqualTo("Test User");
		assertThat(jwt.getAudience()).isNull();
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getIssuedAt()).isNull();
		assertThat(jwt.getExpiresAt()).isNull();
		assertThat(jwt.getNotBefore()).isNull();
		assertThat(jwt.getId()).isNull();
		assertThat(jwt.getClaimAsString("custom-claim")).isEqualTo("foo");

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(WithMockJwt.DEFAULT_HEADER_NAME)).isEqualTo(WithMockJwt.DEFAULT_HEADER_VALUE);
	}

	@Test
	public void custom() throws Exception {
		final SimpleGrantedAuthority machinAuthority = new SimpleGrantedAuthority("machin");
		final SimpleGrantedAuthority choseAuthority = new SimpleGrantedAuthority("chose");

		final WithMockJwt annotation = AnnotationUtils.findAnnotation(CustomFull.class, WithMockJwt.class);

		final JwtAuthenticationToken auth =
				(JwtAuthenticationToken) factory.createSecurityContext(annotation).getAuthentication();
		final Jwt principal = (Jwt) auth.getPrincipal();

		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(auth.getAuthorities().stream().allMatch(a -> a.equals(machinAuthority) || a.equals(choseAuthority)))
				.isTrue();

		assertThat(auth.getCredentials()).isEqualTo(principal);

		assertThat(auth.getDetails()).isNull();

		assertThat(auth.getName()).isEqualTo("truc");

		assertThat(principal.getAudience()).hasSize(2);
		assertThat(principal.getAudience()).contains("test audience", "other audience");
		assertThat(principal.getExpiresAt()).isNull();
		assertThat(principal.getHeaders()).hasSize(1);
		assertThat(principal.getHeaders().get("a")).isEqualTo("1");
		assertThat(principal.getId()).isEqualTo("test ID");
		assertThat(principal.getIssuedAt()).isEqualTo(Instant.parse("2019-03-03T22:35:00.0Z"));
		assertThat(principal.getIssuer()).isEqualTo(new URL("https://test-issuer.org"));
		assertThat(principal.getSubject()).isEqualTo("truc");
		assertThat(principal.getNotBefore()).isNull();
		assertThat(principal.getTokenValue()).isEqualTo(WithMockJwtSecurityContextFactory.DEFAULT_TOKEN_VALUE);
		assertThat(principal.getClaims().get("custom-claim")).isEqualTo("foo");

	}

	public static final class FooParser implements AttributeValueParser<String> {

		@Override
		public String parse(final String value) {
			return "foo";
		}

	}

}
