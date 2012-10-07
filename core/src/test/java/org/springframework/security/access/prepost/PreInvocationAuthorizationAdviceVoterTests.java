package org.springframework.security.access.prepost;

import static org.junit.Assert.assertTrue;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.aop.ProxyMethodInvocation;
import org.springframework.security.access.intercept.aspectj.MethodInvocationAdapter;


@RunWith(MockitoJUnitRunner.class)
public class PreInvocationAuthorizationAdviceVoterTests {
    @Mock
    private PreInvocationAuthorizationAdvice authorizationAdvice;
    private PreInvocationAuthorizationAdviceVoter voter;

    @Before
    public void setUp() {
        voter = new PreInvocationAuthorizationAdviceVoter(authorizationAdvice);
    }

    @Test
    public void supportsMethodInvocation() {
        assertTrue(voter.supports(MethodInvocation.class));
    }

    // SEC-2031
    @Test
    public void supportsProxyMethodInvocation() {
        assertTrue(voter.supports(ProxyMethodInvocation.class));
    }

    @Test
    public void supportsMethodInvocationAdapter() {
        assertTrue(voter.supports(MethodInvocationAdapter.class));
    }
}
