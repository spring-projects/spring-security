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

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ListeningSecurityContextHolderStrategyTests {

	@Test
	public void setContextWhenInvokedThenListenersAreNotified() {
		SecurityContextHolderStrategy delegate = spy(new MockSecurityContextHolderStrategy());
		SecurityContextChangedListener one = mock(SecurityContextChangedListener.class);
		SecurityContextChangedListener two = mock(SecurityContextChangedListener.class);
		SecurityContextHolderStrategy strategy = new ListeningSecurityContextHolderStrategy(delegate, one, two);
		given(delegate.createEmptyContext()).willReturn(new SecurityContextImpl());
		SecurityContext context = strategy.createEmptyContext();
		strategy.setContext(context);
		strategy.getContext();
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
		strategy.getContext();
		verifyNoInteractions(listener);
	}

	@Test
	public void clearContextWhenNoGetContextThenContextIsNotRead() {
		SecurityContextHolderStrategy delegate = mock(SecurityContextHolderStrategy.class);
		SecurityContextChangedListener listener = mock(SecurityContextChangedListener.class);
		SecurityContextHolderStrategy strategy = new ListeningSecurityContextHolderStrategy(delegate, listener);
		Supplier<SecurityContext> context = mock(Supplier.class);
		ArgumentCaptor<SecurityContextChangedEvent> event = ArgumentCaptor.forClass(SecurityContextChangedEvent.class);
		given(delegate.getDeferredContext()).willReturn(context);
		given(delegate.getContext()).willAnswer((invocation) -> context.get());
		strategy.clearContext();
		verifyNoInteractions(context);
		verify(listener).securityContextChanged(event.capture());
		assertThat(event.getValue().isCleared()).isTrue();
		strategy.getContext();
		verify(context).get();
		strategy.clearContext();
		verifyNoMoreInteractions(context);
	}

	@Test
	public void getContextWhenCalledMultipleTimesThenEventPublishedOnce() {
		SecurityContextHolderStrategy delegate = new MockSecurityContextHolderStrategy();
		SecurityContextChangedListener listener = mock(SecurityContextChangedListener.class);
		SecurityContextHolderStrategy strategy = new ListeningSecurityContextHolderStrategy(delegate, listener);
		strategy.setContext(new SecurityContextImpl());
		verifyNoInteractions(listener);
		strategy.getContext();
		verify(listener).securityContextChanged(any());
		strategy.getContext();
		verifyNoMoreInteractions(listener);
	}

	@Test
	public void setContextWhenCalledMultipleTimesThenPublishedEventsAlign() {
		SecurityContextHolderStrategy delegate = new MockSecurityContextHolderStrategy();
		SecurityContextChangedListener listener = mock(SecurityContextChangedListener.class);
		SecurityContextHolderStrategy strategy = new ListeningSecurityContextHolderStrategy(delegate, listener);
		SecurityContext one = new SecurityContextImpl(new TestingAuthenticationToken("user", "pass"));
		SecurityContext two = new SecurityContextImpl(new TestingAuthenticationToken("admin", "pass"));
		ArgumentCaptor<SecurityContextChangedEvent> event = ArgumentCaptor.forClass(SecurityContextChangedEvent.class);
		strategy.setContext(one);
		strategy.setContext(two);
		verifyNoInteractions(listener);
		strategy.getContext();
		verify(listener).securityContextChanged(event.capture());
		assertThat(event.getValue().getOldContext()).isEqualTo(one);
		assertThat(event.getValue().getNewContext()).isEqualTo(two);
		strategy.getContext();
		verifyNoMoreInteractions(listener);
		strategy.setContext(one);
		verifyNoMoreInteractions(listener);
		reset(listener);
		strategy.getContext();
		verify(listener).securityContextChanged(event.capture());
		assertThat(event.getValue().getOldContext()).isEqualTo(two);
		assertThat(event.getValue().getNewContext()).isEqualTo(one);
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
