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

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletContext;
import jakarta.servlet.jsp.tagext.Tag;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.GenericWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 */
@SuppressWarnings("unchecked")
public class AccessControlListTagTests {

	AccessControlListTag tag;

	PermissionEvaluator pe;

	MockPageContext pageContext;

	Authentication bob = new TestingAuthenticationToken("bob", "bobspass", "A");

	@BeforeEach
	@SuppressWarnings("rawtypes")
	public void setup() {
		SecurityContextHolder.getContext().setAuthentication(this.bob);
		this.tag = new AccessControlListTag();
		WebApplicationContext ctx = mock(WebApplicationContext.class);
		this.pe = mock(PermissionEvaluator.class);
		Map beanMap = new HashMap();
		beanMap.put("pe", this.pe);
		given(ctx.getBeansOfType(PermissionEvaluator.class)).willReturn(beanMap);
		given(ctx.getBeanNamesForType(SecurityContextHolderStrategy.class)).willReturn(new String[0]);
		MockServletContext servletCtx = new MockServletContext();
		servletCtx.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx);
		this.pageContext = new MockPageContext(servletCtx, new MockHttpServletRequest(), new MockHttpServletResponse());
		this.tag.setPageContext(this.pageContext);
	}

	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void bodyIsEvaluatedIfAclGrantsAccess() throws Exception {
		Object domainObject = new Object();
		given(this.pe.hasPermission(this.bob, domainObject, "READ")).willReturn(true);
		this.tag.setDomainObject(domainObject);
		this.tag.setHasPermission("READ");
		this.tag.setVar("allowed");
		assertThat(this.tag.getDomainObject()).isSameAs(domainObject);
		assertThat(this.tag.getHasPermission()).isEqualTo("READ");
		assertThat(this.tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) this.pageContext.getAttribute("allowed")).isTrue();
	}

	@Test
	public void securityContextHolderStrategyIsUsedIfConfigured() throws Exception {
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(new SecurityContextImpl(this.bob));
		GenericWebApplicationContext context = new GenericWebApplicationContext();
		context.registerBean(SecurityContextHolderStrategy.class, () -> strategy);
		context.registerBean(PermissionEvaluator.class, () -> this.pe);
		context.refresh();
		MockServletContext servletCtx = new MockServletContext();
		servletCtx.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, context);
		this.pageContext = new MockPageContext(servletCtx, new MockHttpServletRequest(), new MockHttpServletResponse());
		this.tag.setPageContext(this.pageContext);
		Object domainObject = new Object();
		given(this.pe.hasPermission(this.bob, domainObject, "READ")).willReturn(true);
		this.tag.setDomainObject(domainObject);
		this.tag.setHasPermission("READ");
		this.tag.setVar("allowed");
		assertThat(this.tag.getDomainObject()).isSameAs(domainObject);
		assertThat(this.tag.getHasPermission()).isEqualTo("READ");
		assertThat(this.tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) this.pageContext.getAttribute("allowed")).isTrue();
		verify(strategy).getContext();
	}

	@Test
	public void childContext() throws Exception {
		ServletContext servletContext = this.pageContext.getServletContext();
		WebApplicationContext wac = (WebApplicationContext) servletContext
				.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);
		servletContext.removeAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);
		servletContext.setAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher", wac);
		Object domainObject = new Object();
		given(this.pe.hasPermission(this.bob, domainObject, "READ")).willReturn(true);
		this.tag.setDomainObject(domainObject);
		this.tag.setHasPermission("READ");
		this.tag.setVar("allowed");
		assertThat(this.tag.getDomainObject()).isSameAs(domainObject);
		assertThat(this.tag.getHasPermission()).isEqualTo("READ");
		assertThat(this.tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) this.pageContext.getAttribute("allowed")).isTrue();
	}

	// SEC-2022
	@Test
	public void multiHasPermissionsAreSplit() throws Exception {
		Object domainObject = new Object();
		given(this.pe.hasPermission(this.bob, domainObject, "READ")).willReturn(true);
		given(this.pe.hasPermission(this.bob, domainObject, "WRITE")).willReturn(true);
		this.tag.setDomainObject(domainObject);
		this.tag.setHasPermission("READ,WRITE");
		this.tag.setVar("allowed");
		assertThat(this.tag.getDomainObject()).isSameAs(domainObject);
		assertThat(this.tag.getHasPermission()).isEqualTo("READ,WRITE");
		assertThat(this.tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) this.pageContext.getAttribute("allowed")).isTrue();
		verify(this.pe).hasPermission(this.bob, domainObject, "READ");
		verify(this.pe).hasPermission(this.bob, domainObject, "WRITE");
		verifyNoMoreInteractions(this.pe);
	}

	// SEC-2023
	@Test
	public void hasPermissionsBitMaskSupported() throws Exception {
		Object domainObject = new Object();
		given(this.pe.hasPermission(this.bob, domainObject, 1)).willReturn(true);
		given(this.pe.hasPermission(this.bob, domainObject, 2)).willReturn(true);
		this.tag.setDomainObject(domainObject);
		this.tag.setHasPermission("1,2");
		this.tag.setVar("allowed");
		assertThat(this.tag.getDomainObject()).isSameAs(domainObject);
		assertThat(this.tag.getHasPermission()).isEqualTo("1,2");
		assertThat(this.tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) this.pageContext.getAttribute("allowed")).isTrue();
		verify(this.pe).hasPermission(this.bob, domainObject, 1);
		verify(this.pe).hasPermission(this.bob, domainObject, 2);
		verifyNoMoreInteractions(this.pe);
	}

	@Test
	public void hasPermissionsMixedBitMaskSupported() throws Exception {
		Object domainObject = new Object();
		given(this.pe.hasPermission(this.bob, domainObject, 1)).willReturn(true);
		given(this.pe.hasPermission(this.bob, domainObject, "WRITE")).willReturn(true);
		this.tag.setDomainObject(domainObject);
		this.tag.setHasPermission("1,WRITE");
		this.tag.setVar("allowed");
		assertThat(this.tag.getDomainObject()).isSameAs(domainObject);
		assertThat(this.tag.getHasPermission()).isEqualTo("1,WRITE");
		assertThat(this.tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) this.pageContext.getAttribute("allowed")).isTrue();
		verify(this.pe).hasPermission(this.bob, domainObject, 1);
		verify(this.pe).hasPermission(this.bob, domainObject, "WRITE");
		verifyNoMoreInteractions(this.pe);
	}

	@Test
	public void bodyIsSkippedIfAclDeniesAccess() throws Exception {
		Object domainObject = new Object();
		given(this.pe.hasPermission(this.bob, domainObject, "READ")).willReturn(false);
		this.tag.setDomainObject(domainObject);
		this.tag.setHasPermission("READ");
		this.tag.setVar("allowed");
		assertThat(this.tag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat((Boolean) this.pageContext.getAttribute("allowed")).isFalse();
	}

}
