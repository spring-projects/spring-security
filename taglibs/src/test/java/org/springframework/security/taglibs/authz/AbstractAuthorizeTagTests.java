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

package org.springframework.security.taglibs.authz;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 *
 */
public class AbstractAuthorizeTagTests {

	private AbstractAuthorizeTag tag;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private MockServletContext servletContext;

	@Before
	public void setup() {
		this.tag = new AuthzTag();
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.servletContext = new MockServletContext();
	}

	@After
	public void teardown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void privilegeEvaluatorFromRequest() throws IOException {
		String uri = "/something";
		WebInvocationPrivilegeEvaluator expected = mock(WebInvocationPrivilegeEvaluator.class);
		this.tag.setUrl(uri);
		this.request.setAttribute(WebAttributes.WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE, expected);

		this.tag.authorizeUsingUrlCheck();

		verify(expected).isAllowed(eq(""), eq(uri), eq("GET"), any());
	}

	@Test
	public void privilegeEvaluatorFromChildContext() throws IOException {
		String uri = "/something";
		WebInvocationPrivilegeEvaluator expected = mock(WebInvocationPrivilegeEvaluator.class);
		this.tag.setUrl(uri);
		WebApplicationContext wac = mock(WebApplicationContext.class);
		given(wac.getBeansOfType(WebInvocationPrivilegeEvaluator.class))
				.willReturn(Collections.singletonMap("wipe", expected));
		this.servletContext.setAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher", wac);

		this.tag.authorizeUsingUrlCheck();

		verify(expected).isAllowed(eq(""), eq(uri), eq("GET"), any());
	}

	@Test
	@SuppressWarnings("rawtypes")
	public void expressionFromChildContext() throws IOException {
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "pass", "USER"));
		DefaultWebSecurityExpressionHandler expected = new DefaultWebSecurityExpressionHandler();
		this.tag.setAccess("permitAll");
		WebApplicationContext wac = mock(WebApplicationContext.class);
		given(wac.getBeansOfType(SecurityExpressionHandler.class))
				.willReturn(Collections.<String, SecurityExpressionHandler>singletonMap("wipe", expected));
		this.servletContext.setAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher", wac);

		assertThat(this.tag.authorize()).isTrue();
	}

	private class AuthzTag extends AbstractAuthorizeTag {

		@Override
		protected ServletRequest getRequest() {
			return AbstractAuthorizeTagTests.this.request;
		}

		@Override
		protected ServletResponse getResponse() {
			return AbstractAuthorizeTagTests.this.response;
		}

		@Override
		protected ServletContext getServletContext() {
			return AbstractAuthorizeTagTests.this.servletContext;
		}

	}

}
