package org.springframework.security.context;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.security.core.session.SessionDestroyedEvent;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DelegatingApplicationListenerTests {
	@Mock
	SmartApplicationListener delegate;

	ApplicationEvent event;

	DelegatingApplicationListener listener;

	@Before
	public void setup() {
		event = new ApplicationEvent(this) {
		};
		listener = new DelegatingApplicationListener();
		listener.addListener(delegate);
	}

	@Test
	public void processEventNull() {
		listener.onApplicationEvent(null);

		verify(delegate, never()).onApplicationEvent(any(ApplicationEvent.class));
	}

	@Test
	public void processEventSuccess() {
		when(delegate.supportsEventType(event.getClass())).thenReturn(true);
		when(delegate.supportsSourceType(event.getSource().getClass())).thenReturn(true);
		listener.onApplicationEvent(event);

		verify(delegate).onApplicationEvent(event);
	}

	@Test
	public void processEventEventTypeNotSupported() {
		when(delegate.supportsSourceType(event.getSource().getClass())).thenReturn(true);
		listener.onApplicationEvent(event);

		verify(delegate, never()).onApplicationEvent(any(ApplicationEvent.class));
	}

	@Test
	public void processEventSourceTypeNotSupported() {
		when(delegate.supportsEventType(event.getClass())).thenReturn(true);
		listener.onApplicationEvent(event);

		verify(delegate, never()).onApplicationEvent(any(ApplicationEvent.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void addNull() {
		listener.addListener(null);
	}

}
