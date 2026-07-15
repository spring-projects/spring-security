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

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for the {@link SecurityContextHolderStrategy} default methods.
 */
class SecurityContextHolderStrategyTests {

	LegacyStrategy strategy = new LegacyStrategy();

	// gh-18059
	@Test
	void peekDeferredContextWhenNotSetThenReturnsSupplierOfMaterializedContext() {
		Supplier<SecurityContext> deferred = this.strategy.peekDeferredContext();
		assertThat(deferred).isNotNull();
		assertThat(deferred.get()).isSameAs(this.strategy.getContext());
	}

	// gh-18059
	@Test
	void peekDeferredContextWhenContextSetThenReturnsSupplierOfCapturedContext() {
		Authentication authentication = mock(Authentication.class);
		SecurityContext context = new SecurityContextImpl(authentication);
		this.strategy.setContext(context);
		Supplier<SecurityContext> deferred = this.strategy.peekDeferredContext();
		assertThat(deferred).isNotNull();
		// the default captures the value eagerly, so it is not a live view
		this.strategy.clearContext();
		assertThat(deferred.get()).isSameAs(context);
	}

	/**
	 * A pre-5.8 style implementation relying on the interface default methods.
	 */
	static final class LegacyStrategy implements SecurityContextHolderStrategy {

		private @Nullable SecurityContext context;

		@Override
		public void clearContext() {
			this.context = null;
		}

		@Override
		public SecurityContext getContext() {
			if (this.context == null) {
				this.context = createEmptyContext();
			}
			return this.context;
		}

		@Override
		public void setContext(SecurityContext context) {
			this.context = context;
		}

		@Override
		public SecurityContext createEmptyContext() {
			return new SecurityContextImpl();
		}

	}

}
