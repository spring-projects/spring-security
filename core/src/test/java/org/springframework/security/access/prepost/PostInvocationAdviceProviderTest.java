/*
 * Copyright 2002-2021 the original author or authors.
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
public class PostInvocationAdviceProviderTest {

	@Mock
	private PostInvocationAuthorizationAdvice authorizationAdvice;

	private PostInvocationAdviceProvider postInvocationAdviceProvider;

	@BeforeEach
	public void setUp() {
		this.postInvocationAdviceProvider = new PostInvocationAdviceProvider(this.authorizationAdvice);
	}

	@Test
	public void supportsMethodInvocation() {
		assertThat(this.postInvocationAdviceProvider.supports(MethodInvocation.class)).isTrue();
	}

	@Test
	public void supportsProxyMethodInvocation() {
		assertThat(this.postInvocationAdviceProvider.supports(ProxyMethodInvocation.class)).isTrue();
	}

	@Test
	public void supportsMethodInvocationAdapter() {
		assertThat(this.postInvocationAdviceProvider.supports(MethodInvocationAdapter.class)).isTrue();
	}

}
