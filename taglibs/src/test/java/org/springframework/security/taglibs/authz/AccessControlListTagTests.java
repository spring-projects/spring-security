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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.jsp.tagext.Tag;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

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

	@Before
	@SuppressWarnings("rawtypes")
	public void setup() {
		SecurityContextHolder.getContext().setAuthentication(bob);
		tag = new AccessControlListTag();
		WebApplicationContext ctx = mock(WebApplicationContext.class);

		pe = mock(PermissionEvaluator.class);

		Map beanMap = new HashMap();
		beanMap.put("pe", pe);
		when(ctx.getBeansOfType(PermissionEvaluator.class)).thenReturn(beanMap);

		MockServletContext servletCtx = new MockServletContext();
		servletCtx.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx);
		pageContext = new MockPageContext(servletCtx, new MockHttpServletRequest(), new MockHttpServletResponse());
		tag.setPageContext(pageContext);
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void bodyIsEvaluatedIfAclGrantsAccess() throws Exception {
		Object domainObject = new Object();
		when(pe.hasPermission(bob, domainObject, "READ")).thenReturn(true);

		tag.setDomainObject(domainObject);
		tag.setHasPermission("READ");
		tag.setVar("allowed");
		assertThat(tag.getDomainObject()).isSameAs(domainObject);
		assertThat(tag.getHasPermission()).isEqualTo("READ");

		assertThat(tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) pageContext.getAttribute("allowed")).isTrue();
	}

	@Test
	public void childContext() throws Exception {
		ServletContext servletContext = pageContext.getServletContext();
		WebApplicationContext wac = (WebApplicationContext) servletContext
				.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);
		servletContext.removeAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);
		servletContext.setAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher", wac);

		Object domainObject = new Object();
		when(pe.hasPermission(bob, domainObject, "READ")).thenReturn(true);

		tag.setDomainObject(domainObject);
		tag.setHasPermission("READ");
		tag.setVar("allowed");
		assertThat(tag.getDomainObject()).isSameAs(domainObject);
		assertThat(tag.getHasPermission()).isEqualTo("READ");

		assertThat(tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) pageContext.getAttribute("allowed")).isTrue();
	}

	// SEC-2022
	@Test
	public void multiHasPermissionsAreSplit() throws Exception {
		Object domainObject = new Object();
		when(pe.hasPermission(bob, domainObject, "READ")).thenReturn(true);
		when(pe.hasPermission(bob, domainObject, "WRITE")).thenReturn(true);

		tag.setDomainObject(domainObject);
		tag.setHasPermission("READ,WRITE");
		tag.setVar("allowed");
		assertThat(tag.getDomainObject()).isSameAs(domainObject);
		assertThat(tag.getHasPermission()).isEqualTo("READ,WRITE");

		assertThat(tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) pageContext.getAttribute("allowed")).isTrue();
		verify(pe).hasPermission(bob, domainObject, "READ");
		verify(pe).hasPermission(bob, domainObject, "WRITE");
		verifyNoMoreInteractions(pe);
	}

	// SEC-2023
	@Test
	public void hasPermissionsBitMaskSupported() throws Exception {
		Object domainObject = new Object();
		when(pe.hasPermission(bob, domainObject, 1)).thenReturn(true);
		when(pe.hasPermission(bob, domainObject, 2)).thenReturn(true);

		tag.setDomainObject(domainObject);
		tag.setHasPermission("1,2");
		tag.setVar("allowed");
		assertThat(tag.getDomainObject()).isSameAs(domainObject);
		assertThat(tag.getHasPermission()).isEqualTo("1,2");

		assertThat(tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) pageContext.getAttribute("allowed")).isTrue();
		verify(pe).hasPermission(bob, domainObject, 1);
		verify(pe).hasPermission(bob, domainObject, 2);
		verifyNoMoreInteractions(pe);
	}

	@Test
	public void hasPermissionsMixedBitMaskSupported() throws Exception {
		Object domainObject = new Object();
		when(pe.hasPermission(bob, domainObject, 1)).thenReturn(true);
		when(pe.hasPermission(bob, domainObject, "WRITE")).thenReturn(true);

		tag.setDomainObject(domainObject);
		tag.setHasPermission("1,WRITE");
		tag.setVar("allowed");
		assertThat(tag.getDomainObject()).isSameAs(domainObject);
		assertThat(tag.getHasPermission()).isEqualTo("1,WRITE");

		assertThat(tag.doStartTag()).isEqualTo(Tag.EVAL_BODY_INCLUDE);
		assertThat((Boolean) pageContext.getAttribute("allowed")).isTrue();
		verify(pe).hasPermission(bob, domainObject, 1);
		verify(pe).hasPermission(bob, domainObject, "WRITE");
		verifyNoMoreInteractions(pe);
	}

	@Test
	public void bodyIsSkippedIfAclDeniesAccess() throws Exception {
		Object domainObject = new Object();
		when(pe.hasPermission(bob, domainObject, "READ")).thenReturn(false);

		tag.setDomainObject(domainObject);
		tag.setHasPermission("READ");
		tag.setVar("allowed");

		assertThat(tag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat((Boolean) pageContext.getAttribute("allowed")).isFalse();
	}

}
