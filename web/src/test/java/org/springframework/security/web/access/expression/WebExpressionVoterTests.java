package org.springframework.security.web.access.expression;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

import java.util.ArrayList;

/**
 * @author Luke Taylor
 */
@SuppressWarnings({"unchecked"})
public class WebExpressionVoterTests {
    private Authentication user = new TestingAuthenticationToken("user","pass", "X");

    @Test
    public void supportsWebConfigAttributeAndFilterInvocation() throws Exception {
        WebExpressionVoter voter = new WebExpressionVoter();
        assertTrue(voter.supports(new WebExpressionConfigAttribute(mock(Expression.class))));
        assertTrue(voter.supports(FilterInvocation.class));
        assertFalse(voter.supports(MethodInvocation.class));

    }

    @Test
    public void abstainsIfNoAttributeFound() {
        WebExpressionVoter voter = new WebExpressionVoter();
        assertEquals(AccessDecisionVoter.ACCESS_ABSTAIN,
                voter.vote(user, new FilterInvocation("/path", "GET"), SecurityConfig.createList("A", "B", "C")));
    }

    @Test
    public void grantsAccessIfExpressionIsTrueDeniesIfFalse() {
        WebExpressionVoter voter = new WebExpressionVoter();
        Expression ex = mock(Expression.class);
        WebExpressionConfigAttribute weca = new WebExpressionConfigAttribute(ex);
        EvaluationContext ctx = mock(EvaluationContext.class);
        SecurityExpressionHandler eh = mock(SecurityExpressionHandler.class);
        FilterInvocation fi = new FilterInvocation("/path", "GET");
        voter.setExpressionHandler(eh);
        when(eh.createEvaluationContext(user, fi)).thenReturn(ctx);
        when(ex.getValue(ctx, Boolean.class)).thenReturn(Boolean.TRUE).thenReturn(Boolean.FALSE);
        ArrayList attributes = new ArrayList();
        attributes.addAll(SecurityConfig.createList("A","B","C"));
        attributes.add(weca);

        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(user, fi, attributes));

        // Second time false
        assertEquals(AccessDecisionVoter.ACCESS_DENIED, voter.vote(user, fi, attributes));
    }

}
