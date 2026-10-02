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

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class ScopedSecurityContextHolderStrategyTests {

	ScopedSecurityContextHolderStrategy strategy = new ScopedSecurityContextHolderStrategy();

	@Test
	void deferredNotInvoked() {
		Supplier<SecurityContext> deferredContext = mock(Supplier.class);
		ScopedSecurityContextHolderStrategy.getSecuriyContextCarrier().run(() -> {
			try {
				this.strategy.setDeferredContext(deferredContext);
				verifyNoInteractions(deferredContext);
			}
			finally {
				this.strategy.clearContext();
			}
		});
	}

	@Test
	void deferredContext() {
		Authentication authentication = mock(Authentication.class);
		Supplier<SecurityContext> deferredContext = () -> new SecurityContextImpl(authentication);
		ScopedSecurityContextHolderStrategy.runWhere(deferredContext, () -> {
			try {
				this.strategy.setDeferredContext(deferredContext);
				assertThat(this.strategy.getDeferredContext().get()).isEqualTo(deferredContext.get());
				assertThat(this.strategy.getContext()).isEqualTo(deferredContext.get());
			}
			finally {
				this.strategy.clearContext();
			}
		});
	}

	@Test
	void deferredContextValidates() {
		ScopedSecurityContextHolderStrategy.getSecuriyContextCarrier().run(() -> {
			try {
				this.strategy.setDeferredContext(() -> null);
				Supplier<SecurityContext> deferredContext = this.strategy.getDeferredContext();
				assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(deferredContext::get);
			}
			finally {
				this.strategy.clearContext();
			}
		});
	}

	@Test
	void context() {
		Authentication authentication = mock(Authentication.class);
		SecurityContext context = new SecurityContextImpl(authentication);
		ScopedSecurityContextHolderStrategy.getSecuriyContextCarrier().run(() -> {
			try {
				this.strategy.setContext(context);
				assertThat(this.strategy.getContext()).isEqualTo(context);
				assertThat(this.strategy.getDeferredContext().get()).isEqualTo(context);
			}
			finally {
				this.strategy.clearContext();
			}
		});
	}

	@Test
	void contextValidates() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> this.strategy.setContext(null));
	}

	@Test
	void getContextWhenEmptyThenReturnsSameInstance() {
		Authentication authentication = mock(Authentication.class);
		ScopedSecurityContextHolderStrategy.getSecuriyContextCarrier().run(() -> {
			try {
				this.strategy.getContext().setAuthentication(authentication);
				assertThat(this.strategy.getContext().getAuthentication()).isEqualTo(authentication);
			}
			finally {
				this.strategy.clearContext();
			}
		});
	}

	@Test
	void unboundGetContext() {
		assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> this.strategy.getContext());
	}

	@Test
	void unboundSetContext() {
		Authentication authentication = mock(Authentication.class);
		SecurityContext context = new SecurityContextImpl(authentication);
		assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> this.strategy.setContext(context));
	}

}
