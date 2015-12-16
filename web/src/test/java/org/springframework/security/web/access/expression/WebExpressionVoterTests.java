package org.springframework.security.web.access.expression;

import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * @author Luke Taylor
 */
@SuppressWarnings({ "unchecked" })
public class WebExpressionVoterTests {
	private Authentication user = new TestingAuthenticationToken("user", "pass", "X");

	@Test
	public void supportsWebConfigAttributeAndFilterInvocation() throws Exception {
		WebExpressionVoter voter = new WebExpressionVoter();
		assertTrue(voter
				.supports(new WebExpressionConfigAttribute(mock(Expression.class), mock(SecurityEvaluationContextPostProcessor.class))));
		assertThat(voter.supports(FilterInvocation.class)).isTrue();
		assertThat(voter.supports(MethodInvocation.class)).isFalse();

	}

	@Test
	public void abstainsIfNoAttributeFound() {
		WebExpressionVoter voter = new WebExpressionVoter();
		assertEquals(
				AccessDecisionVoter.ACCESS_ABSTAIN,
				voter.vote(user, new FilterInvocation("/path", "GET"),
						SecurityConfig.createList("A", "B", "C")));
	}

	@Test
	public void grantsAccessIfExpressionIsTrueDeniesIfFalse() {
		WebExpressionVoter voter = new WebExpressionVoter();
		Expression ex = mock(Expression.class);
		SecurityEvaluationContextPostProcessor postProcessor = mock(SecurityEvaluationContextPostProcessor.class);
		when(postProcessor.postProcess(any(EvaluationContext.class), any(FilterInvocation.class))).thenAnswer(new Answer<EvaluationContext>() {
			public EvaluationContext answer(InvocationOnMock invocation) throws Throwable {
				return invocation.getArgumentAt(0, EvaluationContext.class);
			}
		});
		WebExpressionConfigAttribute weca = new WebExpressionConfigAttribute(ex,postProcessor);
		EvaluationContext ctx = mock(EvaluationContext.class);
		SecurityExpressionHandler eh = mock(SecurityExpressionHandler.class);
		FilterInvocation fi = new FilterInvocation("/path", "GET");
		voter.setExpressionHandler(eh);
		when(eh.createEvaluationContext(user, fi)).thenReturn(ctx);
		when(ex.getValue(ctx, Boolean.class)).thenReturn(Boolean.TRUE).thenReturn(
				Boolean.FALSE);
		ArrayList attributes = new ArrayList();
		attributes.addAll(SecurityConfig.createList("A", "B", "C"));
		attributes.add(weca);

		assertThat(fi).isCloseTo(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(user, within(attributes)));

		// Second time false
		assertThat(fi).isCloseTo(AccessDecisionVoter.ACCESS_DENIED, voter.vote(user, within(attributes)));
	}

	// SEC-2507
	@Test
	public void supportFilterInvocationSubClass() {
		WebExpressionVoter voter = new WebExpressionVoter();
		assertThat(voter.supports(FilterInvocationChild.class)).isTrue();
	}

	private static class FilterInvocationChild extends FilterInvocation {
		public FilterInvocationChild(ServletRequest request, ServletResponse response,
				FilterChain chain) {
			super(request, response, chain);
		}
	}

	@Test
	public void supportFilterInvocation() {
		WebExpressionVoter voter = new WebExpressionVoter();
		assertThat(voter.supports(FilterInvocation.class)).isTrue();
	}

	@Test
	public void supportsObjectIsFalse() {
		WebExpressionVoter voter = new WebExpressionVoter();
		assertThat(voter.supports(Object.class)).isFalse();
	}
}
