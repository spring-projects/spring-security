/*
 * Copyright 2002-2014 the original author or authors.
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
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.context.SecurityContextRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;

@RunWith(MockitoJUnitRunner.class)
public class SecurityMockMvcRequestPostProcessorsUserTests {

	@Captor
	private ArgumentCaptor<SecurityContext> contextCaptor;

	@Mock
	private SecurityContextRepository repository;

	private MockHttpServletRequest request;

	@Mock
	private GrantedAuthority authority1;

	@Mock
	private GrantedAuthority authority2;

	@Mock
	private MockedStatic<WebTestUtils> webTestUtils;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.webTestUtils.when(() -> WebTestUtils.getSecurityContextRepository(this.request))
				.thenReturn(this.repository);
	}

	@After
	public void cleanup() {
		TestSecurityContextHolder.clearContext();
	}

	@Test
	public void userWithDefaults() {
		String username = "userabc";
		user(username).postProcessRequest(this.request);
		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat(context.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(context.getAuthentication().getName()).isEqualTo(username);
		assertThat(context.getAuthentication().getCredentials()).isEqualTo("password");
		assertThat(context.getAuthentication().getAuthorities()).extracting("authority").containsOnly("ROLE_USER");
	}

	@Test
	public void userWithCustom() {
		String username = "customuser";
		user(username).roles("CUSTOM", "ADMIN").password("newpass").postProcessRequest(this.request);
		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat(context.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(context.getAuthentication().getName()).isEqualTo(username);
		assertThat(context.getAuthentication().getCredentials()).isEqualTo("newpass");
		assertThat(context.getAuthentication().getAuthorities()).extracting("authority").containsOnly("ROLE_CUSTOM",
				"ROLE_ADMIN");
	}

	@Test
	public void userCustomAuthoritiesVarargs() {
		String username = "customuser";
		user(username).authorities(this.authority1, this.authority2).postProcessRequest(this.request);
		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat((List<GrantedAuthority>) context.getAuthentication().getAuthorities()).containsOnly(this.authority1,
				this.authority2);
	}

	@Test
	public void userRolesWithRolePrefixErrors() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> user("user").roles("ROLE_INVALID").postProcessRequest(this.request));
	}

	@Test
	public void userCustomAuthoritiesList() {
		String username = "customuser";
		user(username).authorities(Arrays.asList(this.authority1, this.authority2)).postProcessRequest(this.request);
		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat((List<GrantedAuthority>) context.getAuthentication().getAuthorities()).containsOnly(this.authority1,
				this.authority2);
	}

}
