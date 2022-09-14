/*
 * Copyright 2002-2018 the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

}
