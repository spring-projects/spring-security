package org.springframework.security.taglibs.authz;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.jsp.tagext.Tag;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.WebApplicationContext;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
@SuppressWarnings("unchecked")
public class AccessControlListTagTests {
    AccessControlListTag tag;
    Acl acl;
    MockPageContext pageContext;

    @Before
    public void setup() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("bob","bobspass","A"));
        tag = new AccessControlListTag();
        WebApplicationContext ctx = mock(WebApplicationContext.class);

        AclService service = mock(AclService.class);
        ObjectIdentity oid = mock(ObjectIdentity.class);
        ObjectIdentityRetrievalStrategy oidStrategy = mock(ObjectIdentityRetrievalStrategy.class);
        when(oidStrategy.getObjectIdentity(anyObject())).thenReturn(oid);
        acl = mock(Acl.class);

        when(service.readAclById(any(ObjectIdentity.class), anyList())).thenReturn(acl);
        Map beanMap = new HashMap();
        beanMap.put("service", service);
        when(ctx.getBeansOfType(AclService.class)).thenReturn(beanMap);
        beanMap = new HashMap();
        beanMap.put("oidStrategy", oidStrategy);
        when(ctx.getBeansOfType(ObjectIdentityRetrievalStrategy.class)).thenReturn(beanMap);

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
        when(acl.isGranted(anyList(), anyList(), eq(false))).thenReturn(true);

        tag.setDomainObject(new Object());
        tag.setHasPermission("READ");
        tag.setVar("allowed");

        assertEquals(Tag.EVAL_BODY_INCLUDE, tag.doStartTag());
        assertTrue((Boolean)pageContext.getAttribute("allowed"));
    }

    @Test
    public void bodyIsSkippedIfAclDeniesAccess() throws Exception {
        when(acl.isGranted(anyList(), anyList(), eq(false))).thenReturn(false);

        tag.setDomainObject(new Object());
        tag.setHasPermission("READ");
        tag.setVar("allowed");

        assertEquals(Tag.SKIP_BODY, tag.doStartTag());
        assertFalse((Boolean)pageContext.getAttribute("allowed"));
    }

}
