package org.springframework.security.access.expression.method;

import static org.assertj.core.api.Assertions.*;
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

import java.util.*;

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

		assertThat(ExpressionUtils.evaluateAsBoolean(e, ctx)).isTrue();
	}

	@Test
	public void isAnonymousReturnsTrueIfTrustResolverReportsAnonymous() {
		when(trustResolver.isAnonymous(user)).thenReturn(true);
		assertThat(root.isAnonymous()).isTrue();
	}

	@Test
	public void isAnonymousReturnsFalseIfTrustResolverReportsNonAnonymous() {
		when(trustResolver.isAnonymous(user)).thenReturn(false);
		assertThat(root.isAnonymous()).isFalse();
	}

	@Test
	public void hasPermissionOnDomainObjectReturnsFalseIfPermissionEvaluatorDoes()
			throws Exception {
		final Object dummyDomainObject = new Object();
		final PermissionEvaluator pe = mock(PermissionEvaluator.class);
		ctx.setVariable("domainObject", dummyDomainObject);
		root.setPermissionEvaluator(pe);
		when(pe.hasPermission(user, dummyDomainObject, "ignored")).thenReturn(false);

		assertThat(root.hasPermission(dummyDomainObject, "ignored")).isFalse();

	}

	@Test
	public void hasPermissionOnDomainObjectReturnsTrueIfPermissionEvaluatorDoes()
			throws Exception {
		final Object dummyDomainObject = new Object();
		final PermissionEvaluator pe = mock(PermissionEvaluator.class);
		ctx.setVariable("domainObject", dummyDomainObject);
		root.setPermissionEvaluator(pe);
		when(pe.hasPermission(user, dummyDomainObject, "ignored")).thenReturn(true);

		assertThat(root.hasPermission(dummyDomainObject, "ignored")).isTrue();
	}

	@Test
	public void hasPermissionOnDomainObjectWorksWithIntegerExpressions() throws Exception {
		final Object dummyDomainObject = new Object();
		ctx.setVariable("domainObject", dummyDomainObject);
		final PermissionEvaluator pe = mock(PermissionEvaluator.class);
		root.setPermissionEvaluator(pe);
		when(pe.hasPermission(eq(user), eq(dummyDomainObject), any(Integer.class)))
				.thenReturn(true).thenReturn(true).thenReturn(false);

		Expression e = parser.parseExpression("hasPermission(#domainObject, 0xA)");
		// evaluator returns true
		assertThat(ExpressionUtils.evaluateAsBoolean(e, ctx)).isTrue();
		e = parser.parseExpression("hasPermission(#domainObject, 10)");
		// evaluator returns true
		assertThat(ExpressionUtils.evaluateAsBoolean(e, ctx)).isTrue();
		e = parser.parseExpression("hasPermission(#domainObject, 0xFF)");
		// evaluator returns false, make sure return value matches
		assertThat(ExpressionUtils.evaluateAsBoolean(e, ctx)).isFalse();
	}

	@Test
	public void hasPermissionWorksWithThisObject() throws Exception {
		Object targetObject = new Object() {
			public String getX() {
				return "x";
			}
		};
		root.setThis(targetObject);
		Integer i = 2;
		PermissionEvaluator pe = mock(PermissionEvaluator.class);
		root.setPermissionEvaluator(pe);
		when(pe.hasPermission(user, targetObject, i)).thenReturn(true).thenReturn(false);
		when(pe.hasPermission(user, "x", i)).thenReturn(true);

		Expression e = parser.parseExpression("hasPermission(this, 2)");
		assertThat(ExpressionUtils.evaluateAsBoolean(e, ctx)).isTrue();
		e = parser.parseExpression("hasPermission(this, 2)");
		assertThat(ExpressionUtils.evaluateAsBoolean(e, ctx)).isFalse();

		e = parser.parseExpression("hasPermission(this.x, 2)");
		assertThat(ExpressionUtils.evaluateAsBoolean(e, ctx)).isTrue();
	}
}
