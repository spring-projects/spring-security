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

package org.springframework.security.web.context.request.async;

import java.util.concurrent.Callable;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.NativeWebRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SecurityContextCallableProcessingInterceptorTests {

	@Mock
	private SecurityContext securityContext;

	@Mock
	private Callable<?> callable;

	@Mock
	private NativeWebRequest webRequest;

	@After
	public void clearSecurityContext() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNull() {
		new SecurityContextCallableProcessingInterceptor(null);
	}

	@Test
	public void currentSecurityContext() throws Exception {
		SecurityContextCallableProcessingInterceptor interceptor = new SecurityContextCallableProcessingInterceptor();
		SecurityContextHolder.setContext(this.securityContext);
		interceptor.beforeConcurrentHandling(this.webRequest, this.callable);
		SecurityContextHolder.clearContext();
		interceptor.preProcess(this.webRequest, this.callable);
		assertThat(SecurityContextHolder.getContext()).isSameAs(this.securityContext);
		interceptor.postProcess(this.webRequest, this.callable, null);
		assertThat(SecurityContextHolder.getContext()).isNotSameAs(this.securityContext);
	}

	@Test
	public void specificSecurityContext() throws Exception {
		SecurityContextCallableProcessingInterceptor interceptor = new SecurityContextCallableProcessingInterceptor(
				this.securityContext);
		interceptor.preProcess(this.webRequest, this.callable);
		assertThat(SecurityContextHolder.getContext()).isSameAs(this.securityContext);
		interceptor.postProcess(this.webRequest, this.callable, null);
		assertThat(SecurityContextHolder.getContext()).isNotSameAs(this.securityContext);
	}

}
