/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(
		locations = "classpath:org/springframework/security/web/authentication/DelegatingAuthenticationEntryPointTest-context.xml")
public class DelegatingAuthenticationEntryPointContextTests {

	@Autowired
	private DelegatingAuthenticationEntryPoint daep;

	@Autowired
	@Qualifier("firstAEP")
	private AuthenticationEntryPoint firstAEP;

	@Autowired
	@Qualifier("defaultAEP")
	private AuthenticationEntryPoint defaultAEP;

	@Test
	@DirtiesContext
	public void testFirstAEP() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("192.168.1.10");
		request.addHeader("User-Agent", "Mozilla/5.0");
		this.daep.commence(request, null, null);
		verify(this.firstAEP).commence(request, null, null);
		verify(this.defaultAEP, never()).commence(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(AuthenticationException.class));
	}

	@Test
	@DirtiesContext
	public void testDefaultAEP() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("192.168.1.10");
		this.daep.commence(request, null, null);
		verify(this.defaultAEP).commence(request, null, null);
		verify(this.firstAEP, never()).commence(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(AuthenticationException.class));
	}

}
