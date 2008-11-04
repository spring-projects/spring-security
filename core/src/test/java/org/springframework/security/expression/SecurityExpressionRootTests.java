package org.springframework.security.expression;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelExpressionParser;
import org.springframework.expression.spel.standard.StandardEvaluationContext;
import org.springframework.security.Authentication;
import org.springframework.security.expression.SecurityExpressionRoot;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;


/**
 * Sandbox class for checking feasibility of different security-related expressions.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class SecurityExpressionRootTests {
    SpelExpressionParser parser = new SpelExpressionParser();
    UsernamePasswordAuthenticationToken joe = new UsernamePasswordAuthenticationToken("joe", "password");
    SecurityExpressionRoot root;
    StandardEvaluationContext ctx;

    @Before
    public void createContext() {
        root = new SecurityExpressionRoot(joe);
        ctx = new StandardEvaluationContext();
        ctx.setRootObject(root);
    }

    @Test
    public void canCallMethodsOnVariables() throws Exception {
        ctx.setVariable("var", "somestring");
        Expression e = parser.parseExpression("#var.length() == 10");

        assertTrue(ExpressionUtils.evaluateAsBoolean(e, ctx));
    }

    @Test
    public void hasPermissionWorksWithIntegerExpressions() throws Exception {
        final Object dummyDomainObject = new Object();
        ctx.setVariable("domainObject", dummyDomainObject);

        root.setPermissionEvaluator(new PermissionEvaluator () {
            public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
                // Check the correct target object is passed in
                assertEquals(dummyDomainObject, targetDomainObject);

                return permission instanceof Integer && ((Integer)permission).intValue() == 10;
            }
        });

        Expression e = parser.parseExpression("hasPermission(#domainObject, 0xA)");
        assertTrue(ExpressionUtils.evaluateAsBoolean(e, ctx));
        e = parser.parseExpression("hasPermission(#domainObject, 10)");
        assertTrue(ExpressionUtils.evaluateAsBoolean(e, ctx));
        e = parser.parseExpression("hasPermission(#domainObject, 0xFF)");
        assertFalse(ExpressionUtils.evaluateAsBoolean(e, ctx));
    }
}
