/*
 * Copyright 2002-2022 the original author or authors.
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

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.GenericWebApplicationContext;

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

	@BeforeEach
	public void setup() {
		this.tag = new AuthzTag();
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.servletContext = new MockServletContext();
	}

	@AfterEach
	public void teardown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void privilegeEvaluatorFromRequest() throws IOException {
		WebApplicationContext wac = mock(WebApplicationContext.class);
		this.servletContext.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, wac);
		given(wac.getBeanNamesForType(SecurityContextHolderStrategy.class)).willReturn(new String[0]);
		String uri = "/something";
		WebInvocationPrivilegeEvaluator expected = mock(WebInvocationPrivilegeEvaluator.class);
		this.tag.setUrl(uri);
		this.request.setAttribute(WebAttributes.WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE, expected);
		this.tag.authorizeUsingUrlCheck();
		verify(expected).isAllowed(eq(""), eq(uri), eq("GET"), any());
	}

	@Test
	public void privilegeEvaluatorFromRequestUsesSecurityContextHolderStrategy() throws IOException {
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(new SecurityContextImpl(
				new TestingAuthenticationToken("user", "password", AuthorityUtils.NO_AUTHORITIES)));
		GenericWebApplicationContext wac = new GenericWebApplicationContext();
		wac.registerBean(SecurityContextHolderStrategy.class, () -> strategy);
		wac.refresh();
		this.servletContext.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, wac);
		String uri = "/something";
		WebInvocationPrivilegeEvaluator expected = mock(WebInvocationPrivilegeEvaluator.class);
		this.tag.setUrl(uri);
		this.request.setAttribute(WebAttributes.WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE, expected);
		this.tag.authorizeUsingUrlCheck();
		verify(expected).isAllowed(eq(""), eq(uri), eq("GET"), any());
		verify(strategy).getContext();
	}

	@Test
	public void privilegeEvaluatorFromChildContext() throws IOException {
		String uri = "/something";
		WebInvocationPrivilegeEvaluator expected = mock(WebInvocationPrivilegeEvaluator.class);
		this.tag.setUrl(uri);
		WebApplicationContext wac = mock(WebApplicationContext.class);
		given(wac.getBeansOfType(WebInvocationPrivilegeEvaluator.class))
				.willReturn(Collections.singletonMap("wipe", expected));
		given(wac.getBeanNamesForType(SecurityContextHolderStrategy.class)).willReturn(new String[0]);
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
		given(wac.getBeanNamesForType(SecurityContextHolderStrategy.class)).willReturn(new String[0]);
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
