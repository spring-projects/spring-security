package org.springframework.security.access.expression.method;

import static org.mockito.Mockito.verify;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@RunWith(MockitoJUnitRunner.class)
public class DefaultMethodSecurityExpressionHandlerTests {
    private DefaultMethodSecurityExpressionHandler handler;

    @Mock
    private Authentication authentication;
    @Mock
    private MethodInvocation methodInvocation;
    @Mock
    private AuthenticationTrustResolver trustResolver;

    @Before
    public void setup() {
        handler = new DefaultMethodSecurityExpressionHandler();
    }

    @After
    public void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test(expected = IllegalArgumentException.class)
    public void setTrustResolverNull() {
        handler.setTrustResolver(null);
    }

    @Test
    public void createEvaluationContextCustomTrustResolver() {
        handler.setTrustResolver(trustResolver);

        Expression expression = handler.getExpressionParser().parseExpression("anonymous");
        EvaluationContext context = handler.createEvaluationContext(authentication, methodInvocation);
        expression.getValue(context, Boolean.class);

        verify(trustResolver).isAnonymous(authentication);
    }
}
