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
