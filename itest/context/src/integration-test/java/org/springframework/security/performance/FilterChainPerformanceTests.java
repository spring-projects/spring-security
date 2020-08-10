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
package org.springframework.security.performance;

import org.junit.*;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.StopWatch;

import javax.servlet.http.HttpSession;
import java.util.*;

/**
 * @author Luke Taylor
 * @since 2.0
 */
@ContextConfiguration(locations = { "/filter-chain-performance-app-context.xml" })
@RunWith(SpringJUnit4ClassRunner.class)
public class FilterChainPerformanceTests {

	// Adjust as required
	private static final int N_INVOCATIONS = 1; // 1000

	private static final int N_AUTHORITIES = 2; // 200

	private static StopWatch sw = new StopWatch("Filter Chain Performance Tests");

	private final UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken("bob",
			"bobspassword", createRoles(N_AUTHORITIES));

	private HttpSession session;

	@Autowired
	@Qualifier("fcpMinimalStack")
	private FilterChainProxy minimalStack;

	@Autowired
	@Qualifier("fcpFullStack")
	private FilterChainProxy fullStack;

	@Before
	public void createAuthenticatedSession() {
		session = new MockHttpSession();
		SecurityContextHolder.getContext().setAuthentication(user);
		session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
				SecurityContextHolder.getContext());
		SecurityContextHolder.clearContext();
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@AfterClass
	public static void dumpStopWatch() {
		System.out.println(sw.prettyPrint());
	}

	private MockHttpServletRequest createRequest(String url) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSession(session);
		request.setServletPath(url);
		request.setMethod("GET");
		return request;
	}

	private void runWithStack(FilterChainProxy stack) throws Exception {
		for (int i = 0; i < N_INVOCATIONS; i++) {
			MockHttpServletRequest request = createRequest("/somefile.html");
			stack.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
			session = request.getSession();
		}
	}

	@Test
	public void minimalStackInvocation() throws Exception {
		sw.start("Run with Minimal Filter Stack");
		runWithStack(minimalStack);
		sw.stop();
	}

	@Test
	public void fullStackInvocation() throws Exception {
		sw.start("Run with Full Filter Stack");
		runWithStack(fullStack);
		sw.stop();
	}

	/**
	 * Creates data from 1 to N_AUTHORITIES in steps of 10, performing N_INVOCATIONS for
	 * each
	 */
	@Test
	public void provideDataOnScalingWithNumberOfAuthoritiesUserHas() throws Exception {
		StopWatch sw = new StopWatch("Scaling with nAuthorities");
		for (int user = 0; user < N_AUTHORITIES / 10; user++) {
			int nAuthorities = user == 0 ? 1 : user * 10;
			SecurityContextHolder.getContext().setAuthentication(
					new UsernamePasswordAuthenticationToken("bob", "bobspassword", createRoles(nAuthorities)));
			session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
					SecurityContextHolder.getContext());
			SecurityContextHolder.clearContext();
			sw.start(nAuthorities + " authorities");
			runWithStack(minimalStack);
			System.out.println(sw.shortSummary());
			sw.stop();
		}
		System.out.println(sw.prettyPrint());
	}

	private List<GrantedAuthority> createRoles(int howMany) {
		// This is always the worst case scenario - the required role is ROLE_1, but they
		// are created in reverse order
		GrantedAuthority[] roles = new GrantedAuthority[howMany];

		for (int i = howMany - 1; i >= 0; i--) {
			roles[i] = new SimpleGrantedAuthority("ROLE_" + i);
		}

		return Arrays.asList(roles);
	}

}
