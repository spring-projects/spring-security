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

package org.springframework.security.core.context;

import java.util.function.Supplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class InheritableThreadLocalSecurityContextHolderStrategyTests {

	InheritableThreadLocalSecurityContextHolderStrategy strategy = new InheritableThreadLocalSecurityContextHolderStrategy();

	@AfterEach
	void clearContext() {
		this.strategy.clearContext();
	}

	@Test
	void deferredNotInvoked() {
		Supplier<SecurityContext> deferredContext = mock(Supplier.class);
		this.strategy.setDeferredContext(deferredContext);
		verifyNoInteractions(deferredContext);
	}

	@Test
	void deferredContext() {
		Authentication authentication = mock(Authentication.class);
		Supplier<SecurityContext> deferredContext = () -> new SecurityContextImpl(authentication);
		this.strategy.setDeferredContext(deferredContext);
		assertThat(this.strategy.getDeferredContext().get()).isEqualTo(deferredContext.get());
		assertThat(this.strategy.getContext()).isEqualTo(deferredContext.get());
	}

	@Test
	void deferredContextValidates() {
		this.strategy.setDeferredContext(() -> null);
		Supplier<SecurityContext> deferredContext = this.strategy.getDeferredContext();
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> deferredContext.get());
	}

	@Test
	void context() {
		Authentication authentication = mock(Authentication.class);
		SecurityContext context = new SecurityContextImpl(authentication);
		this.strategy.setContext(context);
		assertThat(this.strategy.getContext()).isEqualTo(context);
		assertThat(this.strategy.getDeferredContext().get()).isEqualTo(context);
	}

	@Test
	void contextValidates() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> this.strategy.setContext(null));
	}

	@Test
	void getContextWhenEmptyThenReturnsSameInstance() {
		Authentication authentication = mock(Authentication.class);
		this.strategy.getContext().setAuthentication(authentication);
		assertThat(this.strategy.getContext().getAuthentication()).isEqualTo(authentication);
	}

}
