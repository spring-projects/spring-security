/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.taglibs.authz;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.*;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.jsp.tagext.Tag;
import java.util.*;

/**
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 */
@SuppressWarnings("unchecked")
public class AccessControlListTagTests {
    AccessControlListTag tag;
    PermissionEvaluator pe;
    MockPageContext pageContext;
    Authentication bob = new TestingAuthenticationToken("bob","bobspass","A");

    @Before
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
        assertSame(domainObject, tag.getDomainObject());
        assertEquals("READ", tag.getHasPermission());

        assertEquals(Tag.EVAL_BODY_INCLUDE, tag.doStartTag());
        assertTrue((Boolean)pageContext.getAttribute("allowed"));
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
        assertSame(domainObject, tag.getDomainObject());
        assertEquals("READ,WRITE", tag.getHasPermission());

        assertEquals(Tag.EVAL_BODY_INCLUDE, tag.doStartTag());
        assertTrue((Boolean)pageContext.getAttribute("allowed"));
        verify(pe).hasPermission(bob, domainObject, "READ");
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

        assertEquals(Tag.SKIP_BODY, tag.doStartTag());
        assertFalse((Boolean)pageContext.getAttribute("allowed"));
    }
}
