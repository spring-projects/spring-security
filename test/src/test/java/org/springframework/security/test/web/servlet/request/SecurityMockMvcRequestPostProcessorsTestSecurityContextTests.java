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

import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareOnlyThisForTest;
import org.powermock.modules.junit4.PowerMockRunner;

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

@RunWith(PowerMockRunner.class)
@PrepareOnlyThisForTest(WebTestUtils.class)
@PowerMockIgnore({ "javax.security.auth.*", "org.w3c.dom.*", "org.xml.sax.*", "org.apache.xerces.*",
		"javax.xml.parsers.*" })
public class SecurityMockMvcRequestPostProcessorsTestSecurityContextTests {

	@Mock
	private SecurityContext context;

	@Mock
	private SecurityContextRepository repository;

	private MockHttpServletRequest request;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		mockWebTestUtils();
	}

	@After
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

	private void mockWebTestUtils() {
		PowerMockito.spy(WebTestUtils.class);
		PowerMockito.when(WebTestUtils.getSecurityContextRepository(this.request)).thenReturn(this.repository);
	}

}
