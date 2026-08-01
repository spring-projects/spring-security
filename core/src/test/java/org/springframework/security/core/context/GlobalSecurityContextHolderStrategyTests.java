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

package org.springframework.security.core.context;

import java.util.function.Supplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class GlobalSecurityContextHolderStrategyTests {

	GlobalSecurityContextHolderStrategy strategy = new GlobalSecurityContextHolderStrategy();

	@AfterEach
	void clearContext() {
		this.strategy.clearContext();
	}

	// gh-18059
	@Test
	void peekDeferredContextWhenEmptyThenReturnsNull() {
		assertThat(this.strategy.peekDeferredContext()).isNull();
	}

	// gh-18059
	@Test
	void peekDeferredContextWhenSetThenReturnsSupplierOfSameContext() {
		Authentication authentication = mock(Authentication.class);
		SecurityContext context = new SecurityContextImpl(authentication);
		this.strategy.setContext(context);
		Supplier<SecurityContext> deferred = this.strategy.peekDeferredContext();
		assertThat(deferred).isNotNull();
		assertThat(deferred.get()).isSameAs(context);
	}

	// gh-18059
	@Test
	void peekDeferredContextWhenContextAutoCreatedThenReturnsSupplierOfSameContext() {
		SecurityContext context = this.strategy.getContext();
		Supplier<SecurityContext> deferred = this.strategy.peekDeferredContext();
		assertThat(deferred).isNotNull();
		assertThat(deferred.get()).isSameAs(context);
	}

}
