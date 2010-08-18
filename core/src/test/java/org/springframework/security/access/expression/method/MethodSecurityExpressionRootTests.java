package org.springframework.security.access.expression.method;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;

/**
 * Tests for {@link MethodSecurityExpressionRoot}
 *
 * @author Luke Taylor
 */
public class MethodSecurityExpressionRootTests {
    SpelExpressionParser parser = new SpelExpressionParser();
    MethodSecurityExpressionRoot root;
    StandardEvaluationContext ctx;
    private AuthenticationTrustResolver trustResolver;
    private Authentication user;


    @Before
    public void createContext() {
        user = mock(Authentication.class);
        root = new MethodSecurityExpressionRoot(user);
        ctx = new StandardEvaluationContext();
        ctx.setRootObject(root);
        trustResolver = mock(AuthenticationTrustResolver.class);
        root.setTrustResolver(trustResolver);
    }

    @Test
    public void canCallMethodsOnVariables() throws Exception {
        ctx.setVariable("var", "somestring");
        Expression e = parser.parseExpression("#var.length() == 10");

        assertTrue(ExpressionUtils.evaluateAsBoolean(e, ctx));
    }

    @Test
    public void isAnonymousReturnsTrueIfTrustResolverReportsAnonymous() {
        when(trustResolver.isAnonymous(user)).thenReturn(true);
        assertTrue(root.isAnonymous());
    }

    @Test
    public void isAnonymousReturnsFalseIfTrustResolverReportsNonAnonymous() {
        when(trustResolver.isAnonymous(user)).thenReturn(false);
        assertFalse(root.isAnonymous());
    }

    @Test
    public void hasPermissionOnDomainObjectReturnsFalseIfPermissionEvaluatorDoes() throws Exception {
        final Object dummyDomainObject = new Object();
        final PermissionEvaluator pe = mock(PermissionEvaluator.class);
        ctx.setVariable("domainObject", dummyDomainObject);
        root.setPermissionEvaluator(pe);
        when(pe.hasPermission(user, dummyDomainObject, "ignored")).thenReturn(false);

        assertFalse(root.hasPermission(dummyDomainObject, "ignored"));

    }

    @Test
    public void hasPermissionOnDomainObjectReturnsTrueIfPermissionEvaluatorDoes() throws Exception {
        final Object dummyDomainObject = new Object();
        final PermissionEvaluator pe = mock(PermissionEvaluator.class);
        ctx.setVariable("domainObject", dummyDomainObject);
        root.setPermissionEvaluator(pe);
        when(pe.hasPermission(user, dummyDomainObject, "ignored")).thenReturn(true);

        assertTrue(root.hasPermission(dummyDomainObject, "ignored"));
    }


    @Test
    public void hasPermissionOnDomainObjectWorksWithIntegerExpressions() throws Exception {
        final Object dummyDomainObject = new Object();
        ctx.setVariable("domainObject", dummyDomainObject);
        final PermissionEvaluator pe = mock(PermissionEvaluator.class);
        root.setPermissionEvaluator(pe);
        when(pe.hasPermission(eq(user), eq(dummyDomainObject), any(Integer.class))).thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);

        Expression e = parser.parseExpression("hasPermission(#domainObject, 0xA)");
        // evaluator returns true
        assertTrue(ExpressionUtils.evaluateAsBoolean(e, ctx));
        e = parser.parseExpression("hasPermission(#domainObject, 10)");
     // evaluator returns true
        assertTrue(ExpressionUtils.evaluateAsBoolean(e, ctx));
        e = parser.parseExpression("hasPermission(#domainObject, 0xFF)");
     // evaluator returns false, make sure return value matches
        assertFalse(ExpressionUtils.evaluateAsBoolean(e, ctx));
    }
}
