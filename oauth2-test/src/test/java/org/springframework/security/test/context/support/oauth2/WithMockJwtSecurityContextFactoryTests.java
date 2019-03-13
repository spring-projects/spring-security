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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.test.context.support.oauth2.properties.NoOpPropertyParser;
import org.springframework.security.test.context.support.oauth2.properties.Property;

@RunWith(MockitoJUnitRunner.class)
public class WithMockJwtSecurityContextFactoryTests {

	@Mock
	private WithMockJwt authAnnotation;

	@Mock
	private Property defaultHeaderAnnotation;

	private WithMockJwtSecurityContextFactory factory;

	@Before
	public void setup() {
		factory = new WithMockJwtSecurityContextFactory();
		when(defaultHeaderAnnotation.name()).thenReturn(WithMockJwt.DEFAULT_HEADER_NAME);
		when(defaultHeaderAnnotation.value())
				.thenReturn(WithMockJwt.DEFAULT_HEADER_VALUE);
		when(defaultHeaderAnnotation.parser())
				.thenReturn(NoOpPropertyParser.class.getName());
	}

	@Test
	public void defaults() {
		when(authAnnotation.name()).thenReturn(WithMockJwt.DEFAULT_AUTH_NAME);
		when(authAnnotation.authorities()).thenReturn(new String[] {});
		when(authAnnotation.headers())
				.thenReturn(new Property[] { defaultHeaderAnnotation });
		when(authAnnotation.claims()).thenReturn(new Property[] {});
		when(authAnnotation.additionalParsers()).thenReturn(new String[] {});

		final Authentication auth = factory.createSecurityContext(authAnnotation)
				.getAuthentication();

		assertThat(auth.getName()).isEqualTo(WithMockJwt.DEFAULT_AUTH_NAME);
		assertThat(auth.getAuthorities()).isEmpty();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue())
				.isEqualTo(WithMockJwtSecurityContextFactory.DEFAULT_TOKEN_VALUE);
		assertThat(jwt.getSubject()).isEqualTo(WithMockJwt.DEFAULT_AUTH_NAME);
		assertThat(jwt.getAudience()).isNull();
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getIssuedAt()).isNull();
		assertThat(jwt.getExpiresAt()).isNull();
		assertThat(jwt.getNotBefore()).isNull();
		assertThat(jwt.getId()).isNull();

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(WithMockJwt.DEFAULT_HEADER_NAME))
				.isEqualTo(WithMockJwt.DEFAULT_HEADER_VALUE);
	}

	@Test
	public void custom() throws Exception {
		final SimpleGrantedAuthority machinAuthority = new SimpleGrantedAuthority(
				"machin");
		final SimpleGrantedAuthority choseAuthority = new SimpleGrantedAuthority("chose");

		when(authAnnotation.name()).thenReturn("bidule");
		when(authAnnotation.authorities()).thenReturn(new String[] {
				machinAuthority.getAuthority(), choseAuthority.getAuthority() });
		when(authAnnotation.headers())
				.thenReturn(new Property[] { defaultHeaderAnnotation });
		when(authAnnotation.claims()).thenReturn(new Property[] {});
		when(authAnnotation.additionalParsers()).thenReturn(new String[] {});

		final Authentication auth = factory.createSecurityContext(authAnnotation)
				.getAuthentication();

		assertThat(auth.getName()).isEqualTo("bidule");
		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(auth.getAuthorities().stream()
				.allMatch(a -> a.equals(machinAuthority) || a.equals(choseAuthority)))
						.isTrue();
		assertThat(auth.getPrincipal()).isInstanceOf(Jwt.class);

		final Jwt jwt = (Jwt) auth.getPrincipal();

		assertThat(auth.getCredentials()).isEqualTo(jwt);
		assertThat(auth.getDetails()).isNull();

		assertThat(jwt.getTokenValue())
				.isEqualTo(WithMockJwtSecurityContextFactory.DEFAULT_TOKEN_VALUE);
		assertThat(jwt.getSubject()).isEqualTo("bidule");

		final Map<String, Object> headers = jwt.getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(WithMockJwt.DEFAULT_HEADER_NAME))
				.isEqualTo(WithMockJwt.DEFAULT_HEADER_VALUE);
	}

}
