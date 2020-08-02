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
import java.util.concurrent.ThreadFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.async.AsyncWebRequest;
import org.springframework.web.context.request.async.CallableProcessingInterceptorAdapter;
import org.springframework.web.context.request.async.WebAsyncManager;
import org.springframework.web.context.request.async.WebAsyncUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class WebAsyncManagerIntegrationFilterTests {

	@Mock
	private SecurityContext securityContext;

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	@Mock
	private AsyncWebRequest asyncWebRequest;

	private WebAsyncManager asyncManager;

	private JoinableThreadFactory threadFactory;

	private MockFilterChain filterChain;

	private WebAsyncManagerIntegrationFilter filter;

	@Before
	public void setUp() {
		this.filterChain = new MockFilterChain();
		this.threadFactory = new JoinableThreadFactory();
		SimpleAsyncTaskExecutor executor = new SimpleAsyncTaskExecutor();
		executor.setThreadFactory(this.threadFactory);
		this.asyncManager = WebAsyncUtils.getAsyncManager(this.request);
		this.asyncManager.setAsyncWebRequest(this.asyncWebRequest);
		this.asyncManager.setTaskExecutor(executor);
		given(this.request.getAttribute(WebAsyncUtils.WEB_ASYNC_MANAGER_ATTRIBUTE)).willReturn(this.asyncManager);
		this.filter = new WebAsyncManagerIntegrationFilter();
	}

	@After
	public void clearSecurityContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void doFilterInternalRegistersSecurityContextCallableProcessor() throws Exception {
		SecurityContextHolder.setContext(this.securityContext);
		this.asyncManager.registerCallableInterceptors(new CallableProcessingInterceptorAdapter() {
			@Override
			public <T> void postProcess(NativeWebRequest request, Callable<T> task, Object concurrentResult) {
				assertThat(SecurityContextHolder.getContext())
						.isNotSameAs(WebAsyncManagerIntegrationFilterTests.this.securityContext);
			}
		});
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		VerifyingCallable verifyingCallable = new VerifyingCallable();
		this.asyncManager.startCallableProcessing(verifyingCallable);
		this.threadFactory.join();
		assertThat(this.asyncManager.getConcurrentResult()).isSameAs(this.securityContext);
	}

	@Test
	public void doFilterInternalRegistersSecurityContextCallableProcessorContextUpdated() throws Exception {
		SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
		this.asyncManager.registerCallableInterceptors(new CallableProcessingInterceptorAdapter() {
			@Override
			public <T> void postProcess(NativeWebRequest request, Callable<T> task, Object concurrentResult) {
				assertThat(SecurityContextHolder.getContext())
						.isNotSameAs(WebAsyncManagerIntegrationFilterTests.this.securityContext);
			}
		});
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		SecurityContextHolder.setContext(this.securityContext);
		VerifyingCallable verifyingCallable = new VerifyingCallable();
		this.asyncManager.startCallableProcessing(verifyingCallable);
		this.threadFactory.join();
		assertThat(this.asyncManager.getConcurrentResult()).isSameAs(this.securityContext);
	}

	private static final class JoinableThreadFactory implements ThreadFactory {

		private Thread t;

		@Override
		public Thread newThread(Runnable r) {
			this.t = new Thread(r);
			return this.t;
		}

		void join() throws InterruptedException {
			this.t.join();
		}

	}

	private class VerifyingCallable implements Callable<SecurityContext> {

		@Override
		public SecurityContext call() {
			return SecurityContextHolder.getContext();
		}

	}

}
