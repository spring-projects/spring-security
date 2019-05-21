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
package org.springframework.security.test.web.servlet.request;

import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.BeanIds;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;

/**
 * Tests for {@link SecurityMockMvcRequestPostProcessors#jwt}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @author Josh Cummings
 * @since 5.2
 */
@RunWith(MockitoJUnitRunner.class)
public class SecurityMockMvcRequestPostProcessorsJwtTests {
	@Captor
	private ArgumentCaptor<SecurityContext> contextCaptor;

	@Mock
	private SecurityContextRepository repository;

	private MockHttpServletRequest request;

	@Mock
	private GrantedAuthority authority1;
	@Mock
	private GrantedAuthority authority2;

	@Before
	public void setup() {
		SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter(this.repository);
		MockServletContext servletContext = new MockServletContext();
		servletContext.setAttribute(BeanIds.SPRING_SECURITY_FILTER_CHAIN,
				new FilterChainProxy(new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, filter)));
		this.request = new MockHttpServletRequest(servletContext);
		WebTestUtils.setSecurityContextRepository(this.request, this.repository);
	}

	@After
	public void cleanup() {
		TestSecurityContextHolder.clearContext();
	}

	@Test
	public void jwtWhenUsingDefaultsThenProducesDefaultJwtAuthentication() {
		jwt().postProcessRequest(this.request);

		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat(context.getAuthentication()).isInstanceOf(
				JwtAuthenticationToken.class);
		JwtAuthenticationToken token = (JwtAuthenticationToken) context.getAuthentication();
		assertThat(token.getAuthorities()).isNotEmpty();
		assertThat(token.getToken()).isNotNull();
		assertThat(token.getToken().getSubject()).isEqualTo("user");
		assertThat(token.getToken().getHeaders().get("alg")).isEqualTo("none");
	}

	@Test
	public void jwtWhenProvidingBuilderConsumerThenProducesJwtAuthentication() {
		String name = new String("user");
		jwt(jwt -> jwt.subject(name)).postProcessRequest(this.request);

		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat(context.getAuthentication()).isInstanceOf(
				JwtAuthenticationToken.class);
		JwtAuthenticationToken token = (JwtAuthenticationToken) context.getAuthentication();
		assertThat(token.getToken().getSubject()).isSameAs(name);
	}

	@Test
	public void jwtWhenProvidingCustomAuthoritiesThenProducesJwtAuthentication() {
		jwt(jwt -> jwt.claim("scope", "ignored authorities"))
				.authorities(this.authority1, this.authority2)
				.postProcessRequest(this.request);

		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat((List<GrantedAuthority>) context.getAuthentication().getAuthorities())
				.containsOnly(this.authority1, this.authority2);
	}

	@Test
	public void jwtWhenProvidingScopedAuthoritiesThenProducesJwtAuthentication() {
		jwt(jwt -> jwt.claim("scope", "scoped authorities"))
				.postProcessRequest(this.request);

		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat((List<GrantedAuthority>) context.getAuthentication().getAuthorities())
				.containsOnly(new SimpleGrantedAuthority("SCOPE_scoped"),
						new SimpleGrantedAuthority("SCOPE_authorities"));
	}

	@Test
	public void jwtWhenProvidingGrantedAuthoritiesThenProducesJwtAuthentication() {
		jwt(jwt -> jwt.claim("scope", "ignored authorities"))
				.authorities(jwt -> Arrays.asList(this.authority1))
				.postProcessRequest(this.request);

		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat((List<GrantedAuthority>) context.getAuthentication().getAuthorities())
				.containsOnly(this.authority1);
	}
}
