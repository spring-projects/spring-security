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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

public class ListeningSecurityContextHolderStrategyTests {

	@Test
	public void setContextWhenInvokedThenListenersAreNotified() {
		SecurityContextHolderStrategy delegate = mock(SecurityContextHolderStrategy.class);
		SecurityContextChangedListener one = mock(SecurityContextChangedListener.class);
		SecurityContextChangedListener two = mock(SecurityContextChangedListener.class);
		SecurityContextHolderStrategy strategy = new ListeningSecurityContextHolderStrategy(delegate, one, two);
		given(delegate.createEmptyContext()).willReturn(new SecurityContextImpl());
		SecurityContext context = strategy.createEmptyContext();
		strategy.setContext(context);
		verify(delegate).setContext(context);
		verify(one).securityContextChanged(any());
		verify(two).securityContextChanged(any());
	}

	@Test
	public void setContextWhenNoChangeToContextThenListenersAreNotNotified() {
		SecurityContextHolderStrategy delegate = mock(SecurityContextHolderStrategy.class);
		SecurityContextChangedListener listener = mock(SecurityContextChangedListener.class);
		SecurityContextHolderStrategy strategy = new ListeningSecurityContextHolderStrategy(delegate, listener);
		SecurityContext context = new SecurityContextImpl();
		given(delegate.getContext()).willReturn(context);
		strategy.setContext(strategy.getContext());
		verify(delegate).setContext(context);
		verifyNoInteractions(listener);
	}

	@Test
	public void constructorWhenNullDelegateThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> new ListeningSecurityContextHolderStrategy((SecurityContextHolderStrategy) null, (event) -> {
				}));
	}

	@Test
	public void constructorWhenNullListenerThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> new ListeningSecurityContextHolderStrategy(new ThreadLocalSecurityContextHolderStrategy(),
						(SecurityContextChangedListener) null));
	}

}
