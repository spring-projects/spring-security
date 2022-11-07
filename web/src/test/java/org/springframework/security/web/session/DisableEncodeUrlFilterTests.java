/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.session;

import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
class DisableEncodeUrlFilterTests {

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	private DisableEncodeUrlFilter filter = new DisableEncodeUrlFilter();

	@Test
	void doFilterDisablesEncodeURL() throws Exception {
		verifyDoFilterDoesNotInteractWithResponse((httpResponse) -> httpResponse.encodeURL("/"));
	}

	@Test
	void doFilterDisablesEncodeRedirectURL() throws Exception {
		verifyDoFilterDoesNotInteractWithResponse((httpResponse) -> httpResponse.encodeRedirectURL("/"));
	}

	private void verifyDoFilterDoesNotInteractWithResponse(Consumer<HttpServletResponse> toInvoke) throws Exception {
		this.filter.doFilter(this.request, this.response, (request, response) -> {
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			toInvoke.accept(httpResponse);
		});
		verifyNoInteractions(this.response);
	}

}
