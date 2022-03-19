/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.web.header.writers;

import java.util.Arrays;
import java.util.Collections;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import org.springframework.security.web.header.HeaderWriter;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for class {@link CompositeHeaderWriter}/.
 *
 * @author Ankur Pathak
 * @since 5.2
 */
public class CompositeHeaderWriterTests {

	@Test
	public void writeHeadersWhenConfiguredWithDelegatesThenInvokesEach() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HeaderWriter one = mock(HeaderWriter.class);
		HeaderWriter two = mock(HeaderWriter.class);
		CompositeHeaderWriter headerWriter = new CompositeHeaderWriter(Arrays.asList(one, two));
		headerWriter.writeHeaders(request, response);
		verify(one).writeHeaders(request, response);
		verify(two).writeHeaders(request, response);
	}

	@Test
	public void constructorWhenPassingEmptyListThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new CompositeHeaderWriter(Collections.emptyList()));
	}

}
