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
package org.springframework.security.web.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

/**
 * @author Rob Winch
 *
 */
public class HttpSessionDestroyedEventTests {

	private MockHttpSession session;

	private HttpSessionDestroyedEvent destroyedEvent;

	@Before
	public void setUp() {
		session = new MockHttpSession();
		session.setAttribute("notcontext", "notcontext");
		session.setAttribute("null", null);
		session.setAttribute("context", new SecurityContextImpl());
		destroyedEvent = new HttpSessionDestroyedEvent(session);
	}

	// SEC-1870
	@Test
	public void getSecurityContexts() {
		List<SecurityContext> securityContexts = destroyedEvent.getSecurityContexts();
		assertThat(securityContexts).hasSize(1);
		assertThat(securityContexts.get(0)).isSameAs(session.getAttribute("context"));
	}

	@Test
	public void getSecurityContextsMulti() {
		session.setAttribute("another", new SecurityContextImpl());
		List<SecurityContext> securityContexts = destroyedEvent.getSecurityContexts();
		assertThat(securityContexts).hasSize(2);
	}

	@Test
	public void getSecurityContextsDiffImpl() {
		session.setAttribute("context", mock(SecurityContext.class));
		List<SecurityContext> securityContexts = destroyedEvent.getSecurityContexts();
		assertThat(securityContexts).hasSize(1);
		assertThat(securityContexts.get(0)).isSameAs(session.getAttribute("context"));
	}

}
