package org.springframework.security.access.method;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.mockito.Matchers;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.util.SimpleMethodInvocation;

import java.lang.reflect.Method;
import java.util.*;

/**
 * @author Luke Taylor
 */
@SuppressWarnings({"unchecked"})
public class DelegatingMethodSecurityMetadataSourceTests {
    DelegatingMethodSecurityMetadataSource mds;

    @Test
    public void returnsNullIfDelegateReturnsNull() throws Exception {
        List sources = new ArrayList();
        MethodSecurityMetadataSource delegate = mock(MethodSecurityMetadataSource.class);
        when(delegate.getAttributes(Matchers.<Method>any(), Matchers.any(Class.class))).thenReturn(null);
        sources.add(delegate);
        mds = new DelegatingMethodSecurityMetadataSource(sources);
        assertSame(sources, mds.getMethodSecurityMetadataSources());
        assertTrue(mds.getAllConfigAttributes().isEmpty());
        MethodInvocation mi = new SimpleMethodInvocation(null, String.class.getMethod("toString"));
        assertNull(mds.getAttributes(mi));
        // Exercise the cached case
        assertNull(mds.getAttributes(mi));
    }

    @Test
    public void returnsDelegateAttributes() throws Exception {
        List sources = new ArrayList();
        MethodSecurityMetadataSource delegate = mock(MethodSecurityMetadataSource.class);
        ConfigAttribute ca = mock(ConfigAttribute.class);
        List attributes = Arrays.asList(ca);
        Method toString = String.class.getMethod("toString");
        when(delegate.getAttributes(toString, String.class)).thenReturn(attributes);
        sources.add(delegate);
        mds = new DelegatingMethodSecurityMetadataSource(sources);
        assertSame(sources, mds.getMethodSecurityMetadataSources());
        assertTrue(mds.getAllConfigAttributes().isEmpty());
        MethodInvocation mi = new SimpleMethodInvocation("", toString);
        assertSame(attributes, mds.getAttributes(mi));
        // Exercise the cached case
        assertSame(attributes, mds.getAttributes(mi));
        assertTrue(mds.getAttributes(new SimpleMethodInvocation(null, String.class.getMethod("length"))).isEmpty());
    }

}
