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

package org.springframework.security.access.prepost;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.aop.ProxyMethodInvocation;
import org.springframework.security.access.intercept.aspectj.MethodInvocationAdapter;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
public class PreInvocationAuthorizationAdviceVoterTests {

	@Mock
	private PreInvocationAuthorizationAdvice authorizationAdvice;

	private PreInvocationAuthorizationAdviceVoter voter;

	@BeforeEach
	public void setUp() {
		this.voter = new PreInvocationAuthorizationAdviceVoter(this.authorizationAdvice);
	}

	@Test
	public void supportsMethodInvocation() {
		assertThat(this.voter.supports(MethodInvocation.class)).isTrue();
	}

	// SEC-2031
	@Test
	public void supportsProxyMethodInvocation() {
		assertThat(this.voter.supports(ProxyMethodInvocation.class)).isTrue();
	}

	@Test
	public void supportsMethodInvocationAdapter() {
		assertThat(this.voter.supports(MethodInvocationAdapter.class)).isTrue();
	}

}
