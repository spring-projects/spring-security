/*
 * Copyright 2002-2013 the original author or authors.
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

import java.util.Collections;
import java.util.EnumSet;
import java.util.EventListener;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;
import javax.servlet.SessionTrackingMode;

import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.filter.DelegatingFilterProxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willDoNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
public class AbstractSecurityWebApplicationInitializerTests {

	private static final EnumSet<DispatcherType> DEFAULT_DISPATCH = EnumSet.of(DispatcherType.REQUEST,
			DispatcherType.ERROR, DispatcherType.ASYNC);

	@Test
	public void onStartupWhenDefaultContextThenRegistersSpringSecurityFilterChain() {
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);
		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		new AbstractSecurityWebApplicationInitializer() {
		}.onStartup(context);

		assertProxyDefaults(proxyCaptor.getValue());

		verify(registration).addMappingForUrlPatterns(DEFAULT_DISPATCH, false, "/*");
		verify(registration).setAsyncSupported(true);
		verifyNoAddListener(context);
	}

	@Test
	public void onStartupWhenConfigurationClassThenAddsContextLoaderListener() {
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		new AbstractSecurityWebApplicationInitializer(MyRootConfiguration.class) {
		}.onStartup(context);

		assertProxyDefaults(proxyCaptor.getValue());

		verify(registration).addMappingForUrlPatterns(DEFAULT_DISPATCH, false, "/*");
		verify(registration).setAsyncSupported(true);
		verify(context).addListener(any(ContextLoaderListener.class));
	}

	@Test
	public void onStartupWhenEnableHttpSessionEventPublisherIsTrueThenAddsHttpSessionEventPublisher() {
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected boolean enableHttpSessionEventPublisher() {
				return true;
			}
		}.onStartup(context);

		assertProxyDefaults(proxyCaptor.getValue());

		verify(registration).addMappingForUrlPatterns(DEFAULT_DISPATCH, false, "/*");
		verify(registration).setAsyncSupported(true);
		verify(context).addListener(HttpSessionEventPublisher.class.getName());
	}

	@Test
	public void onStartupWhenCustomSecurityDispatcherTypesThenUses() {
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected EnumSet<DispatcherType> getSecurityDispatcherTypes() {
				return EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR, DispatcherType.FORWARD);
			}
		}.onStartup(context);

		assertProxyDefaults(proxyCaptor.getValue());

		verify(registration).addMappingForUrlPatterns(
				EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR, DispatcherType.FORWARD), false, "/*");
		verify(registration).setAsyncSupported(true);
		verifyNoAddListener(context);
	}

	@Test
	public void onStartupWhenCustomDispatcherWebApplicationContextSuffixThenUses() {
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected String getDispatcherWebApplicationContextSuffix() {
				return "dispatcher";
			}
		}.onStartup(context);

		DelegatingFilterProxy proxy = proxyCaptor.getValue();
		assertThat(proxy.getContextAttribute())
				.isEqualTo("org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher");
		assertThat(proxy).hasFieldOrPropertyWithValue("targetBeanName", "springSecurityFilterChain");

		verify(registration).addMappingForUrlPatterns(DEFAULT_DISPATCH, false, "/*");
		verify(registration).setAsyncSupported(true);
		verifyNoAddListener(context);
	}

	@Test
	public void onStartupWhenSpringSecurityFilterChainAlreadyRegisteredThenException() {
		ServletContext context = mock(ServletContext.class);

		assertThatCode(() -> new AbstractSecurityWebApplicationInitializer() {
		}.onStartup(context)).isInstanceOf(IllegalStateException.class)
				.hasMessage("Duplicate Filter registration for 'springSecurityFilterChain'. "
						+ "Check to ensure the Filter is only configured once.");
	}

	@Test
	public void onStartupWhenInsertFiltersThenInserted() {
		Filter filter1 = mock(Filter.class);
		Filter filter2 = mock(Filter.class);
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);
		given(context.addFilter(anyString(), eq(filter1))).willReturn(registration);
		given(context.addFilter(anyString(), eq(filter2))).willReturn(registration);

		new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
				insertFilters(context, filter1, filter2);
			}
		}.onStartup(context);

		assertProxyDefaults(proxyCaptor.getValue());

		verify(registration, times(3)).addMappingForUrlPatterns(DEFAULT_DISPATCH, false, "/*");
		verify(registration, times(3)).setAsyncSupported(true);
		verifyNoAddListener(context);
		verify(context).addFilter(anyString(), eq(filter1));
		verify(context).addFilter(anyString(), eq(filter2));
	}

	@Test
	public void onStartupWhenDuplicateFilterInsertedThenException() {
		Filter filter1 = mock(Filter.class);
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		assertThatCode(() -> new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
				insertFilters(context, filter1);
			}
		}.onStartup(context)).isInstanceOf(IllegalStateException.class).hasMessage(
				"Duplicate Filter registration for 'object'. " + "Check to ensure the Filter is only configured once.");

		assertProxyDefaults(proxyCaptor.getValue());

		verify(registration).addMappingForUrlPatterns(DEFAULT_DISPATCH, false, "/*");
		verify(context).addFilter(anyString(), eq(filter1));
	}

	@Test
	public void onStartupWhenInsertFiltersEmptyThenException() {
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		assertThatCode(() -> new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
				insertFilters(context);
			}
		}.onStartup(context)).isInstanceOf(IllegalArgumentException.class)
				.hasMessage("filters cannot be null or empty");

		assertProxyDefaults(proxyCaptor.getValue());
	}

	@Test
	public void onStartupWhenNullFilterInsertedThenException() {
		Filter filter = mock(Filter.class);
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);
		given(context.addFilter(anyString(), eq(filter))).willReturn(registration);

		assertThatCode(() -> new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
				insertFilters(context, filter, null);
			}
		}.onStartup(context)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("filters cannot contain null values");

		verify(context, times(2)).addFilter(anyString(), any(Filter.class));
	}

	@Test
	public void onStartupWhenAppendFiltersThenAppended() {
		Filter filter1 = mock(Filter.class);
		Filter filter2 = mock(Filter.class);
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);
		given(context.addFilter(anyString(), eq(filter1))).willReturn(registration);
		given(context.addFilter(anyString(), eq(filter2))).willReturn(registration);

		new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
				appendFilters(context, filter1, filter2);
			}
		}.onStartup(context);

		verify(registration, times(1)).addMappingForUrlPatterns(DEFAULT_DISPATCH, false, "/*");
		verify(registration, times(2)).addMappingForUrlPatterns(DEFAULT_DISPATCH, true, "/*");
		verify(registration, times(3)).setAsyncSupported(true);
		verifyNoAddListener(context);
		verify(context, times(3)).addFilter(anyString(), any(Filter.class));
	}

	@Test
	public void onStartupWhenDuplicateFilterAppendedThenException() {
		Filter filter1 = mock(Filter.class);
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		assertThatCode(() -> new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
				appendFilters(context, filter1);
			}
		}.onStartup(context)).isInstanceOf(IllegalStateException.class).hasMessage(
				"Duplicate Filter registration for 'object'. " + "Check to ensure the Filter is only configured once.");

		assertProxyDefaults(proxyCaptor.getValue());

		verify(registration).addMappingForUrlPatterns(DEFAULT_DISPATCH, false, "/*");
		verify(context).addFilter(anyString(), eq(filter1));
	}

	@Test
	public void onStartupWhenAppendFiltersEmptyThenException() {
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		assertThatCode(() -> new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
				appendFilters(context);
			}
		}.onStartup(context)).isInstanceOf(IllegalArgumentException.class)
				.hasMessage("filters cannot be null or empty");

		assertProxyDefaults(proxyCaptor.getValue());
	}

	@Test
	public void onStartupWhenNullFilterAppendedThenException() {
		Filter filter = mock(Filter.class);
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);

		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);
		given(context.addFilter(anyString(), eq(filter))).willReturn(registration);

		assertThatCode(() -> new AbstractSecurityWebApplicationInitializer() {
			@Override
			protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
				appendFilters(context, filter, null);
			}
		}.onStartup(context)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("filters cannot contain null values");

		verify(context, times(2)).addFilter(anyString(), any(Filter.class));
	}

	@Test
	public void onStartupWhenDefaultsThenSessionTrackingModes() {
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);
		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		ArgumentCaptor<Set<SessionTrackingMode>> modesCaptor = ArgumentCaptor
				.forClass(new HashSet<SessionTrackingMode>() {
				}.getClass());
		willDoNothing().given(context).setSessionTrackingModes(modesCaptor.capture());

		new AbstractSecurityWebApplicationInitializer() {
		}.onStartup(context);

		assertProxyDefaults(proxyCaptor.getValue());

		Set<SessionTrackingMode> modes = modesCaptor.getValue();
		assertThat(modes).hasSize(1);
		assertThat(modes).containsExactly(SessionTrackingMode.COOKIE);
	}

	@Test
	public void onStartupWhenSessionTrackingModesConfiguredThenUsed() {
		ServletContext context = mock(ServletContext.class);
		FilterRegistration.Dynamic registration = mock(FilterRegistration.Dynamic.class);

		ArgumentCaptor<DelegatingFilterProxy> proxyCaptor = ArgumentCaptor.forClass(DelegatingFilterProxy.class);
		given(context.addFilter(eq("springSecurityFilterChain"), proxyCaptor.capture())).willReturn(registration);

		ArgumentCaptor<Set<SessionTrackingMode>> modesCaptor = ArgumentCaptor
				.forClass(new HashSet<SessionTrackingMode>() {
				}.getClass());
		willDoNothing().given(context).setSessionTrackingModes(modesCaptor.capture());

		new AbstractSecurityWebApplicationInitializer() {
			@Override
			public Set<SessionTrackingMode> getSessionTrackingModes() {
				return Collections.singleton(SessionTrackingMode.SSL);
			}
		}.onStartup(context);

		assertProxyDefaults(proxyCaptor.getValue());

		Set<SessionTrackingMode> modes = modesCaptor.getValue();
		assertThat(modes).hasSize(1);
		assertThat(modes).containsExactly(SessionTrackingMode.SSL);
	}

	@Test
	public void defaultFilterNameEqualsSpringSecurityFilterChain() {
		assertThat(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
				.isEqualTo("springSecurityFilterChain");
	}

	private static void verifyNoAddListener(ServletContext context) {
		verify(context, times(0)).addListener(anyString());
		verify(context, times(0)).addListener(any(EventListener.class));
		verify(context, times(0)).addListener(any(Class.class));
	}

	private static void assertProxyDefaults(DelegatingFilterProxy proxy) {
		assertThat(proxy.getContextAttribute()).isNull();
		assertThat(proxy).hasFieldOrPropertyWithValue("targetBeanName", "springSecurityFilterChain");
	}

	@Configuration
	static class MyRootConfiguration {

	}

}
