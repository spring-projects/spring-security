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

package org.springframework.security.integration;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.TestMockHttpServletRequests;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ContextConfiguration(locations = { "/http-extra-fsi-app-context.xml" })
@ExtendWith(SpringExtension.class)
public class HttpNamespaceWithMultipleInterceptorsTests {

	@Autowired
	private FilterChainProxy fcp;

	@Test
	public void requestThatIsMatchedByDefaultInterceptorIsAllowed() throws Exception {
		MockHttpServletRequest request = TestMockHttpServletRequests.get("/somefile.html").build();
		request.setSession(createAuthenticatedSession("ROLE_0", "ROLE_1", "ROLE_2"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.fcp.doFilter(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(200);
	}

	@Test
	public void securedUrlAccessIsRejectedWithoutRequiredRole() throws Exception {
		MockHttpServletRequest request = TestMockHttpServletRequests.get("/secure/somefile.html").build();
		request.setSession(createAuthenticatedSession("ROLE_0"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.fcp.doFilter(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(403);
	}

	public HttpSession createAuthenticatedSession(String... roles) {
		MockHttpSession session = new MockHttpSession();
		SecurityContextHolder.getContext()
			.setAuthentication(new TestingAuthenticationToken("bob", "bobspassword", roles));
		session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
				SecurityContextHolder.getContext());
		SecurityContextHolder.clearContext();
		return session;
	}

}
