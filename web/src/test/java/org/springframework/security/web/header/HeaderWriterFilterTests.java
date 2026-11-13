/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.header;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for the {@code HeadersFilter}
 *
 * @author Marten Deinum
 * @author Rob Winch
 * @since 3.2
 */
@ExtendWith(MockitoExtension.class)
public class HeaderWriterFilterTests {

	@Mock
	private HeaderWriter writer1;

	@Mock
	private HeaderWriter writer2;

	@Test
	public void noHeadersConfigured() {
		assertThatIllegalArgumentException().isThrownBy(() -> new HeaderWriterFilter(new ArrayList<>()));
	}

	@Test
	public void constructorNullWriters() {
		assertThatIllegalArgumentException().isThrownBy(() -> new HeaderWriterFilter(null));
	}

	@Test
	public void additionalHeadersShouldBeAddedToTheResponse() throws Exception {
		List<HeaderWriter> headerWriters = new ArrayList<>();
		headerWriters.add(this.writer1);
		headerWriters.add(this.writer2);
		HeaderWriterFilter filter = new HeaderWriterFilter(headerWriters);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain();
		filter.doFilter(request, response, filterChain);
		verify(this.writer1).writeHeaders(request, response);
		verify(this.writer2).writeHeaders(request, response);
		HeaderWriterFilter.HeaderWriterRequest wrappedRequest = (HeaderWriterFilter.HeaderWriterRequest) filterChain
			.getRequest();
		assertThat(wrappedRequest.getRequest()).isEqualTo(request); // verify the
																	// filterChain
																	// continued
	}

	// gh-2953
	@Test
	public void headersDelayed() throws Exception {
		HeaderWriterFilter filter = new HeaderWriterFilter(Arrays.<HeaderWriter>asList(this.writer1));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, (request1, response1) -> {
			verifyNoMoreInteractions(HeaderWriterFilterTests.this.writer1);
			response1.flushBuffer();
			verify(HeaderWriterFilterTests.this.writer1).writeHeaders(any(HttpServletRequest.class),
					any(HttpServletResponse.class));
		});
		verifyNoMoreInteractions(this.writer1);
	}

	// gh-5499
	@Test
	public void doFilterWhenRequestContainsIncludeThenHeadersStillWritten() throws Exception {
		HeaderWriterFilter filter = new HeaderWriterFilter(Collections.singletonList(this.writer1));
		MockHttpServletRequest mockRequest = new MockHttpServletRequest();
		MockHttpServletResponse mockResponse = new MockHttpServletResponse();
		filter.doFilter(mockRequest, mockResponse, (request, response) -> {
			verifyNoMoreInteractions(HeaderWriterFilterTests.this.writer1);
			request.getRequestDispatcher("/").include(request, response);
			verify(HeaderWriterFilterTests.this.writer1).writeHeaders(any(HttpServletRequest.class),
					any(HttpServletResponse.class));
		});
		verifyNoMoreInteractions(this.writer1);
	}

	// gh-9175
	@Test
	public void doFilterWhenWriteHeadersCalledConcurrentlyThenHeadersWrittenOnlyOnce() throws Exception {
		List<HeaderWriter> headerWriters = new ArrayList<>();
		headerWriters.add(this.writer1);
		HeaderWriterFilter filter = new HeaderWriterFilter(headerWriters);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, (req, resp) ->
		// Calling writeHeaders() directly simulates the race window where an
		// async thread enters writeHeaders() via onResponseCommitted() but has
		// not yet called disableOnResponseCommitted().
		((HeaderWriterFilter.HeaderWriterResponse) resp).writeHeaders());
		// The finally block in doHeadersAfter also calls writeHeaders().
		// Without the fix, the header writers would be invoked twice.
		verify(this.writer1).writeHeaders(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verifyNoMoreInteractions(this.writer1);
	}

	@Test
	public void headersWrittenAtBeginningOfRequest() throws Exception {
		HeaderWriterFilter filter = new HeaderWriterFilter(Collections.singletonList(this.writer1));
		filter.setShouldWriteHeadersEagerly(true);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, (request1, response1) -> verify(HeaderWriterFilterTests.this.writer1)
			.writeHeaders(any(HttpServletRequest.class), any(HttpServletResponse.class)));
		verifyNoMoreInteractions(this.writer1);
	}

	// gh-15510
	@Test
	public void doFilterWhenResponseCommittedWhileWritingHeadersThenCommitWaitsForHeaders() throws Exception {
		// With asynchronous processing, such as a controller returning a
		// StreamingResponseBody, two threads use the response at the same time:
		//
		// - The request thread runs the filter chain, which starts asynchronous
		// processing and returns. The finally block in doHeadersAfter then writes the
		// headers.
		// - The async thread writes the body and flushes the response, which calls
		// onResponseCommitted() and then commits the response. Committing makes the
		// servlet container write out the headers.
		//
		// If the async thread commits while the request thread is still adding headers,
		// the container writes out a header list that is being modified. Tomcat's
		// MimeHeaders is not thread-safe, so a header that has been added but not yet
		// named is sent as ": ", which clients reject.
		//
		// The header writer below blocks, holding the request thread in the middle of
		// writing the headers so that the async thread commits at exactly that point.
		CountDownLatch writingHeaders = new CountDownLatch(1);
		CountDownLatch finishWritingHeaders = new CountDownLatch(1);
		HeaderWriter writer = (request, response) -> {
			writingHeaders.countDown();
			await(finishWritingHeaders);
			response.setHeader("X-Test", "value");
		};
		HeaderWriterFilter filter = new HeaderWriterFilter(Collections.singletonList(writer));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		AtomicReference<ServletResponse> wrappedResponse = new AtomicReference<>();
		// 1. Request thread: the filter chain returns without committing the response,
		// as it does once asynchronous processing has started, so the finally block
		// writes the headers. It stops inside the header writer above.
		Thread requestThread = startDaemon(
				() -> filter.doFilter(request, response, (req, res) -> wrappedResponse.set(res)));
		try {
			assertThat(writingHeaders.await(5, TimeUnit.SECONDS)).isTrue();
			// 2. Async thread: flushes the response while the request thread is still
			// writing the headers.
			Thread asyncThread = startDaemon(() -> wrappedResponse.get().flushBuffer());
			// 3. The async thread must wait for the headers. Without the fix it commits
			// the response immediately, while the headers are still being written.
			awaitBlockedOrTerminated(asyncThread);
			assertThat(response.isCommitted()).isFalse();
			// 4. The request thread finishes writing the headers, and only then does the
			// async thread commit the response.
			finishWritingHeaders.countDown();
			asyncThread.join(TimeUnit.SECONDS.toMillis(5));
			requestThread.join(TimeUnit.SECONDS.toMillis(5));
			assertThat(response.isCommitted()).isTrue();
			assertThat(response.getHeader("X-Test")).isEqualTo("value");
		}
		finally {
			finishWritingHeaders.countDown();
		}
	}

	private static void await(CountDownLatch latch) {
		try {
			assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException(ex);
		}
	}

	private static Thread startDaemon(ThrowingCallable callable) {
		Thread thread = new Thread(() -> {
			try {
				callable.call();
			}
			catch (Throwable ex) {
				throw new IllegalStateException(ex);
			}
		});
		thread.setDaemon(true);
		thread.start();
		return thread;
	}

	private static void awaitBlockedOrTerminated(Thread thread) throws InterruptedException {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
		while (thread.isAlive() && thread.getState() != Thread.State.BLOCKED) {
			assertThat(System.nanoTime()).isLessThan(deadline);
			Thread.sleep(10);
		}
	}

}
