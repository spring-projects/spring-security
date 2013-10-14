package org.springframework.security.web.access.expression;


import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Collection;
import java.util.LinkedHashMap;

/**
 * @author Luke Taylor
 */
public class ExpressionBasedFilterInvocationSecurityMetadataSourceTests {

    @Test
    public void expectedAttributeIsReturned() {
        final String expression = "hasRole('X')";
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
        requestMap.put(AnyRequestMatcher.INSTANCE, SecurityConfig.createList(expression));
        ExpressionBasedFilterInvocationSecurityMetadataSource mds =
                new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, new DefaultWebSecurityExpressionHandler());
        assertEquals(1, mds.getAllConfigAttributes().size());
        Collection<ConfigAttribute> attrs = mds.getAttributes(new FilterInvocation("/path", "GET"));
        assertEquals(1, attrs.size());
        WebExpressionConfigAttribute attribute = (WebExpressionConfigAttribute) attrs.toArray()[0];
        assertNull(attribute.getAttribute());
        assertEquals(expression, attribute.getAuthorizeExpression().getExpressionString());
        assertEquals(expression, attribute.toString());
    }

    @Test(expected=IllegalArgumentException.class)
    public void invalidExpressionIsRejected() throws Exception {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
        requestMap.put(AnyRequestMatcher.INSTANCE, SecurityConfig.createList("hasRole('X'"));
        ExpressionBasedFilterInvocationSecurityMetadataSource mds =
                new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, new DefaultWebSecurityExpressionHandler());
    }
}
