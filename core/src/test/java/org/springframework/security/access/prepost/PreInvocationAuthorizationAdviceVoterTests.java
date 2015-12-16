package org.springframework.security.access.prepost;

import static org.assertj.core.api.Assertions.assertThat;

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
		assertThat(voter.supports(MethodInvocation.class)).isTrue();
	}

	// SEC-2031
	@Test
	public void supportsProxyMethodInvocation() {
		assertThat(voter.supports(ProxyMethodInvocation.class)).isTrue();
	}

	@Test
	public void supportsMethodInvocationAdapter() {
		assertThat(voter.supports(MethodInvocationAdapter.class)).isTrue();
	}
}
