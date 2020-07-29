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

package org.springframework.security.data.repository.query;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

public class SecurityEvaluationContextExtensionTests {

	SecurityEvaluationContextExtension securityExtension;

	@Before
	public void setup() {
		this.securityExtension = new SecurityEvaluationContextExtension();
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void getRootObjectSecurityContextHolderAuthenticationNull() {
		getRoot().getAuthentication();
	}

	@Test
	public void getRootObjectSecurityContextHolderAuthentication() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(authentication);

		assertThat(getRoot().getAuthentication()).isSameAs(authentication);
	}

	@Test
	public void getRootObjectExplicitAuthenticationOverridesSecurityContextHolder() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);

		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(authentication);

		assertThat(getRoot().getAuthentication()).isSameAs(explicit);
	}

	@Test
	public void getRootObjectExplicitAuthentication() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);

		assertThat(getRoot().getAuthentication()).isSameAs(explicit);
	}

	private SecurityExpressionRoot getRoot() {
		return this.securityExtension.getRootObject();
	}

}
