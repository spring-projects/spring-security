/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.web.authentication.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;

public class SessionFixationProtectionStrategyTest {

	private Authentication authentication;
	private MockHttpServletRequest httpServletRequest;
	private MockHttpServletResponse httpServletResponse;
	private MockHttpSession httpSession;
	private SessionFixationProtectionStrategy sessionFixationProtectionStrategy;

	@Before
	public void setUp() {
		this.authentication = mock(Authentication.class);
		this.httpServletRequest = new MockHttpServletRequest();
		this.httpServletResponse = new MockHttpServletResponse();
		this.httpSession = new MockHttpSession();
		this.httpServletRequest.setSession(httpSession);
		this.sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
	}

	@Test
	public void createsANewSessionWithAllAttributesTransferredAndTheSessionMaxInactiveInterval() {
		String name = "jaswanth";
		List<String> hobbies = Arrays.asList("reading", "blah");
		httpSession.setAttribute("name", name);
		httpSession.setAttribute("hobbies", hobbies);
		httpSession.setMaxInactiveInterval(2480);

		sessionFixationProtectionStrategy.onAuthentication(authentication, httpServletRequest, httpServletResponse);

		HttpSession newHttpSession = httpServletRequest.getSession(false);
		assertThat(httpSession.hashCode()).isNotEqualTo(newHttpSession.hashCode());
		assertThat(newHttpSession.getAttribute("name")).isEqualTo(name);
		assertThat(newHttpSession.getAttribute("hobbies")).isEqualTo(hobbies);
		assertThat(newHttpSession.getMaxInactiveInterval()).isEqualTo(2480);
	}

	@Test
	public void shouldNotTransferAttributesIfNotRequested() {
		httpSession.setAttribute("name", "jaswanth");
		httpSession.setMaxInactiveInterval(2480);
		this.sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);

		sessionFixationProtectionStrategy.onAuthentication(authentication, httpServletRequest, httpServletResponse);

		HttpSession newHttpSession = httpServletRequest.getSession(false);
		assertThat(httpSession.hashCode()).isNotEqualTo(newHttpSession.hashCode());
		assertThat(newHttpSession.getAttributeNames().hasMoreElements()).isFalse();
		assertThat(newHttpSession.getMaxInactiveInterval()).isEqualTo(2480);
	}
}
