/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.access.expression.method;

import static org.assertj.core.api.Assertions.*;
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
	public void canCallMethodsOnVariables() {
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
	public void hasPermissionOnDomainObjectReturnsFalseIfPermissionEvaluatorDoes() {
		final Object dummyDomainObject = new Object();
		final PermissionEvaluator pe = mock(PermissionEvaluator.class);
		ctx.setVariable("domainObject", dummyDomainObject);
		root.setPermissionEvaluator(pe);
		when(pe.hasPermission(user, dummyDomainObject, "ignored")).thenReturn(false);

		assertThat(root.hasPermission(dummyDomainObject, "ignored")).isFalse();

	}

	@Test
	public void hasPermissionOnDomainObjectReturnsTrueIfPermissionEvaluatorDoes() {
		final Object dummyDomainObject = new Object();
		final PermissionEvaluator pe = mock(PermissionEvaluator.class);
		ctx.setVariable("domainObject", dummyDomainObject);
		root.setPermissionEvaluator(pe);
		when(pe.hasPermission(user, dummyDomainObject, "ignored")).thenReturn(true);

		assertThat(root.hasPermission(dummyDomainObject, "ignored")).isTrue();
	}

	@Test
	public void hasPermissionOnDomainObjectWorksWithIntegerExpressions() {
		final Object dummyDomainObject = new Object();
		ctx.setVariable("domainObject", dummyDomainObject);
		final PermissionEvaluator pe = mock(PermissionEvaluator.class);
		root.setPermissionEvaluator(pe);
		when(pe.hasPermission(eq(user), eq(dummyDomainObject), any(Integer.class))).thenReturn(true).thenReturn(true)
				.thenReturn(false);

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
	public void hasPermissionWorksWithThisObject() {
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
