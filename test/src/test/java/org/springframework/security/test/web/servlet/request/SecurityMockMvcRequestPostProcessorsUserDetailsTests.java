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

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.context.SecurityContextRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;

@ExtendWith(MockitoExtension.class)
public class SecurityMockMvcRequestPostProcessorsUserDetailsTests {

	@Captor
	private ArgumentCaptor<SecurityContext> contextCaptor;

	@Mock
	private SecurityContextRepository repository;

	private MockHttpServletRequest request;

	@Mock
	private UserDetails userDetails;

	@Mock
	private MockedStatic<WebTestUtils> webTestUtils;

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.webTestUtils.when(() -> WebTestUtils.getSecurityContextRepository(this.request))
				.thenReturn(this.repository);
	}

	@AfterEach
	public void cleanup() {
		TestSecurityContextHolder.clearContext();
	}

	@Test
	public void userDetails() {
		user(this.userDetails).postProcessRequest(this.request);
		verify(this.repository).saveContext(this.contextCaptor.capture(), eq(this.request),
				any(HttpServletResponse.class));
		SecurityContext context = this.contextCaptor.getValue();
		assertThat(context.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(context.getAuthentication().getPrincipal()).isSameAs(this.userDetails);
	}

}
