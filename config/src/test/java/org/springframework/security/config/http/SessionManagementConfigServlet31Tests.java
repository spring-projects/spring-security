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
package org.springframework.security.config.http;

import java.lang.reflect.Method;
import javax.servlet.Filter;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.util.ReflectionUtils;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

/**
 * @author Rob Winch
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ ReflectionUtils.class, Method.class })
@PowerMockIgnore({ "org.w3c.dom.*", "org.xml.sax.*", "org.apache.xerces.*", "javax.xml.parsers.*" })
public class SessionManagementConfigServlet31Tests {
	private static final String XML_AUTHENTICATION_MANAGER = "<authentication-manager>"
			+ "  <authentication-provider>" + "    <user-service>"
			+ "      <user name='user' password='{noop}password' authorities='ROLE_USER' />"
			+ "    </user-service>" + "  </authentication-provider>"
			+ "</authentication-manager>";

	@Mock
	Method method;

	MockHttpServletRequest request;
	MockHttpServletResponse response;
	MockFilterChain chain;

	ConfigurableApplicationContext context;

	Filter springSecurityFilterChain;

	@Before
	public void setup() {
		request = new MockHttpServletRequest("GET", "");
		response = new MockHttpServletResponse();
		chain = new MockFilterChain();
	}

	@After
	public void teardown() {
		if (context != null) {
			context.close();
		}
	}

	@Test
	public void changeSessionIdThenPreserveParameters() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.getSession();
		request.setServletPath("/login");
		request.setMethod("POST");
		request.setParameter("username", "user");
		request.setParameter("password", "password");

		request.getSession().setAttribute("attribute1", "value1");

		String id = request.getSession().getId();

		loadContext("<http>\n" + "        <form-login/>\n"
				+ "        <session-management/>\n" + "        <csrf disabled='true'/>\n"
				+ "    </http>" + XML_AUTHENTICATION_MANAGER);

		springSecurityFilterChain.doFilter(request, response, chain);


		assertThat(request.getSession().getId()).isNotEqualTo(id);
		assertThat(request.getSession().getAttribute("attribute1")).isEqualTo("value1");
	}

	@Test
	public void changeSessionId() throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.getSession();
		request.setServletPath("/login");
		request.setMethod("POST");
		request.setParameter("username", "user");
		request.setParameter("password", "password");

		String id = request.getSession().getId();

		loadContext("<http>\n"
				+ "        <form-login/>\n"
				+ "        <session-management session-fixation-protection='changeSessionId'/>\n"
				+ "        <csrf disabled='true'/>\n" + "    </http>"
				+ XML_AUTHENTICATION_MANAGER);

		springSecurityFilterChain.doFilter(request, response, chain);

		assertThat(request.getSession().getId()).isNotEqualTo(id);

	}

	private void loadContext(String context) {
		this.context = new InMemoryXmlApplicationContext(context);
		this.springSecurityFilterChain = this.context.getBean(
				"springSecurityFilterChain", Filter.class);
	}

	private void login(Authentication auth) {
		HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
		HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(
				request, response);
		repo.loadContext(requestResponseHolder);

		SecurityContextImpl securityContextImpl = new SecurityContextImpl();
		securityContextImpl.setAuthentication(auth);
		repo.saveContext(securityContextImpl, requestResponseHolder.getRequest(),
				requestResponseHolder.getResponse());
	}
}
