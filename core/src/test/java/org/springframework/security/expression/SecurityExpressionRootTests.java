package org.springframework.security.expression;

import static org.junit.Assert.*;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.junit.Before;
import org.junit.Test;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelExpressionParser;
import org.springframework.expression.spel.standard.StandardEvaluationContext;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.expression.SecurityExpressionRoot;


/**
 * Sandbox class for checking feasibility of different security-related expressions.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class SecurityExpressionRootTests {
    SpelExpressionParser parser = new SpelExpressionParser();
    SecurityExpressionRoot root;
    StandardEvaluationContext ctx;
    Mockery jmock = new Mockery();
    private AuthenticationTrustResolver trustResolver;
    private Authentication user;


    @Before
    public void createContext() {
        user = jmock.mock(Authentication.class);
        root = new SecurityExpressionRoot(user);
        ctx = new StandardEvaluationContext();
        ctx.setRootObject(root);
        trustResolver = jmock.mock(AuthenticationTrustResolver.class);
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
        jmock.checking(new Expectations() {{
            oneOf(trustResolver).isAnonymous(user); will(returnValue(true));
        }});
        assertTrue(root.isAnonymous());
    }

    @Test
    public void isAnonymousReturnsFalseIfTrustResolverReportsNonAnonymous() {
        jmock.checking(new Expectations() {{
            oneOf(trustResolver).isAnonymous(user); will(returnValue(false));
        }});
        assertFalse(root.isAnonymous());
    }

    @Test
    public void hasPermissionOnDomainObjectReturnsFalseIfPermissionEvaluatorDoes() throws Exception {
        final Object dummyDomainObject = new Object();
        final PermissionEvaluator pe = jmock.mock(PermissionEvaluator.class);
        ctx.setVariable("domainObject", dummyDomainObject);
        root.setPermissionEvaluator(pe);
        jmock.checking(new Expectations() {{
            oneOf(pe).hasPermission(user, dummyDomainObject, "ignored"); will(returnValue(false));
        }});

        assertFalse(root.hasPermission(dummyDomainObject, "ignored"));
    }

    @Test
    public void hasPermissionOnDomainObjectReturnsTrueIfPermissionEvaluatorDoes() throws Exception {
        final Object dummyDomainObject = new Object();
        final PermissionEvaluator pe = jmock.mock(PermissionEvaluator.class);
        ctx.setVariable("domainObject", dummyDomainObject);
        root.setPermissionEvaluator(pe);
        jmock.checking(new Expectations() {{
            oneOf(pe).hasPermission(user, dummyDomainObject, "ignored"); will(returnValue(true));
        }});

        assertTrue(root.hasPermission(dummyDomainObject, "ignored"));
    }


    @Test
    public void hasPermissionOnDomainObjectWorksWithIntegerExpressions() throws Exception {
        final Object dummyDomainObject = new Object();
        ctx.setVariable("domainObject", dummyDomainObject);
        final PermissionEvaluator pe = jmock.mock(PermissionEvaluator.class);
        root.setPermissionEvaluator(pe);

        jmock.checking(new Expectations() {{
            exactly(3).of(pe).hasPermission(with(user), with(dummyDomainObject), with(any(Integer.class)));
                will(onConsecutiveCalls(returnValue(true), returnValue(true), returnValue(false)));
        }});

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
