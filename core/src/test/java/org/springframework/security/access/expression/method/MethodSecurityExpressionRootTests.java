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

import org.junit.Before;
import org.junit.Test;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

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
		this.user = mock(Authentication.class);
		this.root = new MethodSecurityExpressionRoot(this.user);
		this.ctx = new StandardEvaluationContext();
		this.ctx.setRootObject(this.root);
		this.trustResolver = mock(AuthenticationTrustResolver.class);
		this.root.setTrustResolver(this.trustResolver);
	}

	@Test
	public void canCallMethodsOnVariables() {
		this.ctx.setVariable("var", "somestring");
		Expression e = this.parser.parseExpression("#var.length() == 10");

		assertThat(ExpressionUtils.evaluateAsBoolean(e, this.ctx)).isTrue();
	}

	@Test
	public void isAnonymousReturnsTrueIfTrustResolverReportsAnonymous() {
		given(this.trustResolver.isAnonymous(this.user)).willReturn(true);
		assertThat(this.root.isAnonymous()).isTrue();
	}

	@Test
	public void isAnonymousReturnsFalseIfTrustResolverReportsNonAnonymous() {
		given(this.trustResolver.isAnonymous(this.user)).willReturn(false);
		assertThat(this.root.isAnonymous()).isFalse();
	}

	@Test
	public void hasPermissionOnDomainObjectReturnsFalseIfPermissionEvaluatorDoes() {
		final Object dummyDomainObject = new Object();
		final PermissionEvaluator pe = mock(PermissionEvaluator.class);
		this.ctx.setVariable("domainObject", dummyDomainObject);
		this.root.setPermissionEvaluator(pe);
		given(pe.hasPermission(this.user, dummyDomainObject, "ignored")).willReturn(false);

		assertThat(this.root.hasPermission(dummyDomainObject, "ignored")).isFalse();

	}

	@Test
	public void hasPermissionOnDomainObjectReturnsTrueIfPermissionEvaluatorDoes() {
		final Object dummyDomainObject = new Object();
		final PermissionEvaluator pe = mock(PermissionEvaluator.class);
		this.ctx.setVariable("domainObject", dummyDomainObject);
		this.root.setPermissionEvaluator(pe);
		given(pe.hasPermission(this.user, dummyDomainObject, "ignored")).willReturn(true);

		assertThat(this.root.hasPermission(dummyDomainObject, "ignored")).isTrue();
	}

	@Test
	public void hasPermissionOnDomainObjectWorksWithIntegerExpressions() {
		final Object dummyDomainObject = new Object();
		this.ctx.setVariable("domainObject", dummyDomainObject);
		final PermissionEvaluator pe = mock(PermissionEvaluator.class);
		this.root.setPermissionEvaluator(pe);
		given(pe.hasPermission(eq(this.user), eq(dummyDomainObject), any(Integer.class))).willReturn(true, true, false);

		Expression e = this.parser.parseExpression("hasPermission(#domainObject, 0xA)");
		// evaluator returns true
		assertThat(ExpressionUtils.evaluateAsBoolean(e, this.ctx)).isTrue();
		e = this.parser.parseExpression("hasPermission(#domainObject, 10)");
		// evaluator returns true
		assertThat(ExpressionUtils.evaluateAsBoolean(e, this.ctx)).isTrue();
		e = this.parser.parseExpression("hasPermission(#domainObject, 0xFF)");
		// evaluator returns false, make sure return value matches
		assertThat(ExpressionUtils.evaluateAsBoolean(e, this.ctx)).isFalse();
	}

	@Test
	public void hasPermissionWorksWithThisObject() {
		Object targetObject = new Object() {
			public String getX() {
				return "x";
			}
		};
		this.root.setThis(targetObject);
		Integer i = 2;
		PermissionEvaluator pe = mock(PermissionEvaluator.class);
		this.root.setPermissionEvaluator(pe);
		given(pe.hasPermission(this.user, targetObject, i)).willReturn(true, false);
		given(pe.hasPermission(this.user, "x", i)).willReturn(true);

		Expression e = this.parser.parseExpression("hasPermission(this, 2)");
		assertThat(ExpressionUtils.evaluateAsBoolean(e, this.ctx)).isTrue();
		e = this.parser.parseExpression("hasPermission(this, 2)");
		assertThat(ExpressionUtils.evaluateAsBoolean(e, this.ctx)).isFalse();

		e = this.parser.parseExpression("hasPermission(this.x, 2)");
		assertThat(ExpressionUtils.evaluateAsBoolean(e, this.ctx)).isTrue();
	}

}
