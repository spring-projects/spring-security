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

import jakarta.servlet.jsp.JspException;
import jakarta.servlet.jsp.tagext.Tag;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;

/**
 * @author Francois Beausoleil
 * @author Luke Taylor
 */
@ExtendWith(MockitoExtension.class)
public class AuthorizeTagTests {

	@Mock
	private PermissionEvaluator permissionEvaluator;

	private JspAuthorizeTag authorizeTag;

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private final TestingAuthenticationToken currentUser = new TestingAuthenticationToken("abc", "123",
			"ROLE SUPERVISOR", "ROLE_TELLER");

	@BeforeEach
	public void setUp() {
		SecurityContextHolder.getContext().setAuthentication(this.currentUser);
		StaticWebApplicationContext ctx = new StaticWebApplicationContext();
		BeanDefinitionBuilder webExpressionHandler = BeanDefinitionBuilder
				.rootBeanDefinition(DefaultWebSecurityExpressionHandler.class);
		webExpressionHandler.addPropertyValue("permissionEvaluator", this.permissionEvaluator);
		ctx.registerBeanDefinition("expressionHandler", webExpressionHandler.getBeanDefinition());
		ctx.registerSingleton("wipe", MockWebInvocationPrivilegeEvaluator.class);
		MockServletContext servletCtx = new MockServletContext();
		servletCtx.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx);
		this.authorizeTag = new JspAuthorizeTag();
		this.authorizeTag.setPageContext(new MockPageContext(servletCtx, this.request, new MockHttpServletResponse()));
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	// access attribute tests
	@Test
	public void taglibsDocumentationHasPermissionOr() throws Exception {
		Object domain = new Object();
		this.request.setAttribute("domain", domain);
		this.authorizeTag.setAccess("hasPermission(#domain,'read') or hasPermission(#domain,'write')");
		given(this.permissionEvaluator.hasPermission(eq(this.currentUser), eq(domain), anyString())).willReturn(true);
		assertThat(this.authorizeTag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
	}

	@Test
	public void skipsBodyIfNoAuthenticationPresent() throws Exception {
		SecurityContextHolder.clearContext();
		this.authorizeTag.setAccess("permitAll");
		assertThat(this.authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	@Test
	public void skipsBodyIfAccessExpressionDeniesAccess() throws Exception {
		this.authorizeTag.setAccess("denyAll");
		assertThat(this.authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	@Test
	public void showsBodyIfAccessExpressionAllowsAccess() throws Exception {
		this.authorizeTag.setAccess("permitAll");
		assertThat(this.authorizeTag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
	}

	@Test
	public void requestAttributeIsResolvedAsElVariable() throws JspException {
		this.request.setAttribute("blah", "blah");
		this.authorizeTag.setAccess("#blah == 'blah'");
		assertThat(this.authorizeTag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
	}

	// url attribute tests
	@Test
	public void skipsBodyWithUrlSetIfNoAuthenticationPresent() throws Exception {
		SecurityContextHolder.clearContext();
		this.authorizeTag.setUrl("/something");
		assertThat(this.authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	@Test
	public void skipsBodyIfUrlIsNotAllowed() throws Exception {
		this.authorizeTag.setUrl("/notallowed");
		assertThat(this.authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	@Test
	public void evaluatesBodyIfUrlIsAllowed() throws Exception {
		this.authorizeTag.setUrl("/allowed");
		this.authorizeTag.setMethod("GET");
		assertThat(this.authorizeTag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
	}

	@Test
	public void skipsBodyIfMethodIsNotAllowed() throws Exception {
		this.authorizeTag.setUrl("/allowed");
		this.authorizeTag.setMethod("POST");
		assertThat(this.authorizeTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
	}

	public static class MockWebInvocationPrivilegeEvaluator implements WebInvocationPrivilegeEvaluator {

		@Override
		public boolean isAllowed(String uri, Authentication authentication) {
			return "/allowed".equals(uri);
		}

		@Override
		public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
			return "/allowed".equals(uri) && (method == null || "GET".equals(method));
		}

	}

}
