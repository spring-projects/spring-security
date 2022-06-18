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

package org.springframework.security.web.context;

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 */
class SecurityContextRepositoryTests {

	SecurityContextRepository repository = spy(SecurityContextRepository.class);

	@Test
	void loadContextHttpRequestResponseHolderWhenInvokeSupplierTwiceThenOnlyInvokesLoadContextOnce() {
		given(this.repository.loadContext(any(HttpRequestResponseHolder.class))).willReturn(new SecurityContextImpl());
		Supplier<SecurityContext> deferredContext = this.repository.loadContext(mock(HttpServletRequest.class));
		verify(this.repository).loadContext(any(HttpServletRequest.class));
		deferredContext.get();
		verify(this.repository).loadContext(any(HttpRequestResponseHolder.class));
		deferredContext.get();
		verifyNoMoreInteractions(this.repository);
	}

}
