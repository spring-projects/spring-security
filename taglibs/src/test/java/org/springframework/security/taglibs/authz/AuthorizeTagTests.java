/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.StaticWebApplicationContext;

/**
 * @author Francois Beausoleil
 * @author Luke Taylor
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthorizeTagTests {
	// ~ Instance fields
	// ================================================================================================

	@Mock
	private PermissionEvaluator permissionEvaluator;
	private JspAuthorizeTag authorizeTag;
	private MockHttpServletRequest request = new MockHttpServletRequest();
	private final TestingAuthenticationToken currentUser = new TestingAuthenticationToken(
			"abc", "123", "ROLE SUPERVISOR", "ROLE_TELLER");

	// ~ Methods
	// ========================================================================================================

	@Before
	public void setUp() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(currentUser);
		StaticWebApplicationContext ctx = new StaticWebApplicationContext();

		BeanDefinitionBuilder webExpressionHandler = BeanDefinitionBuilder
				.rootBeanDefinition(DefaultWebSecurityExpressionHandler.class);
		webExpressionHandler.addPropertyValue("permissionEvaluator", permissionEvaluator);

		ctx.registerBeanDefinition("expressionHandler",
				webExpressionHandler.getBeanDefinition());
		ctx.registerSingleton("wipe", MockWebInvocationPrivilegeEvaluator.class);
		MockServletContext servletCtx = new MockServletContext();
		servletCtx.setAttribute(
				WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx);
		authorizeTag = new JspAuthorizeTag();
		authorizeTag.setPageContext(new MockPageContext(servletCtx, request,
				new MockHttpServletResponse()));
	}

	@After
	public void tearDown() throws Exception {
		SecurityContextHolder.clearContext();
	}

	// access attribute tests

	@Test
	public void taglibsDocumentationHasPermissionOr() throws Exception {
		Object domain = new Object();
		request.setAttribute("domain", domain);
		authorizeTag
				.setAccess("hasPermission(#domain,'read') or hasPermission(#domain,'write')");
		when(permissionEvaluator.hasPermission(eq(currentUser), eq(domain), anyString()))
				.thenReturn(true);

		assertThat(authorizeTag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
	}

	@Test
	public void skipsBodyIfNoAuthenticationPresent() throws Exception {
		SecurityContextHolder.clearContext();
		authorizeTag.setAccess("permitAll");
		assertThat(authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	@Test
	public void skipsBodyIfAccessExpressionDeniesAccess() throws Exception {
		authorizeTag.setAccess("denyAll");
		assertThat(authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	@Test
	public void showsBodyIfAccessExpressionAllowsAccess() throws Exception {
		authorizeTag.setAccess("permitAll");
		assertThat(authorizeTag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
	}

	@Test
	public void requestAttributeIsResolvedAsElVariable() throws JspException {
		request.setAttribute("blah", "blah");
		authorizeTag.setAccess("#blah == 'blah'");
		assertThat(authorizeTag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
	}

	// url attribute tests
	@Test
	public void skipsBodyWithUrlSetIfNoAuthenticationPresent() throws Exception {
		SecurityContextHolder.clearContext();
		authorizeTag.setUrl("/something");
		assertThat(authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	@Test
	public void skipsBodyIfUrlIsNotAllowed() throws Exception {
		authorizeTag.setUrl("/notallowed");
		assertThat(authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	@Test
	public void evaluatesBodyIfUrlIsAllowed() throws Exception {
		authorizeTag.setUrl("/allowed");
		authorizeTag.setMethod("GET");
		assertThat(authorizeTag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
	}

	@Test
	public void skipsBodyIfMethodIsNotAllowed() throws Exception {
		authorizeTag.setUrl("/allowed");
		authorizeTag.setMethod("POST");
		assertThat(authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	public static class MockWebInvocationPrivilegeEvaluator implements
			WebInvocationPrivilegeEvaluator {

		public boolean isAllowed(String uri, Authentication authentication) {
			return "/allowed".equals(uri);
		}

		public boolean isAllowed(String contextPath, String uri, String method,
				Authentication authentication) {
			return "/allowed".equals(uri) && (method == null || "GET".equals(method));
		}
	}
}
