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
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.context.SecurityContextRepository;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.testSecurityContext;

@ExtendWith(MockitoExtension.class)
public class SecurityMockMvcRequestPostProcessorsTestSecurityContextTests {

	@Mock
	private SecurityContext context;

	@Mock
	private SecurityContextRepository repository;

	@Mock
	private MockedStatic<WebTestUtils> webTestUtils;

	private MockHttpServletRequest request;

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
	public void testSecurityContextSaves() {
		TestSecurityContextHolder.setContext(this.context);
		testSecurityContext().postProcessRequest(this.request);
		verify(this.repository).saveContext(eq(this.context), eq(this.request), any(HttpServletResponse.class));
	}

	// Ensure it does not fail if TestSecurityContextHolder is not initialized
	@Test
	public void testSecurityContextNoContext() {
		testSecurityContext().postProcessRequest(this.request);
		verify(this.repository, never()).saveContext(any(SecurityContext.class), eq(this.request),
				any(HttpServletResponse.class));
	}

}
