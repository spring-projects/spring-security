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

package org.springframework.security.config.annotation.web;

import java.util.List;
import java.util.stream.Stream;

import jakarta.servlet.DispatcherType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * Tests for {@link AbstractRequestMatcherRegistry}.
 *
 * @author Joe Grandja
 * @author Marcus Da Coregio
 */
public class AbstractRequestMatcherRegistryTests {

	private static final ObjectPostProcessor<Object> NO_OP_OBJECT_POST_PROCESSOR = new ObjectPostProcessor<Object>() {
		@Override
		public <O> O postProcess(O object) {
			return object;
		}
	};

	private TestRequestMatcherRegistry matcherRegistry;

	private WebApplicationContext context;

	@BeforeEach
	public void setUp() {
		this.matcherRegistry = new TestRequestMatcherRegistry();
		this.context = mock(WebApplicationContext.class);
		ObjectProvider<ObjectPostProcessor<Object>> postProcessors = mock(ObjectProvider.class);
		ResolvableType type = ResolvableType.forClassWithGenerics(ObjectPostProcessor.class, Object.class);
		ObjectProvider<ObjectPostProcessor<Object>> given = this.context.getBeanProvider(type);
		given(given).willReturn(postProcessors);
		given(postProcessors.getObject()).willReturn(NO_OP_OBJECT_POST_PROCESSOR);
		given(this.context.getBeanProvider(PathPatternRequestMatcher.Builder.class))
			.willReturn(new SingleObjectProvider<>(PathPatternRequestMatcher.withDefaults()));
		this.matcherRegistry.setApplicationContext(this.context);
	}

	@Test
	public void regexMatchersWhenHttpMethodAndPatternParamsThenReturnRegexRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry
			.requestMatchers(new RegexRequestMatcher("/a.*", HttpMethod.GET.name()));
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(RegexRequestMatcher.class);
	}

	@Test
	public void regexMatchersWhenPatternParamThenReturnRegexRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry
			.requestMatchers(new RegexRequestMatcher("/a.*", null));
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(RegexRequestMatcher.class);
	}

	@Test
	public void pathPatternWhenHttpMethodAndPatternParamsThenReturnPathPatternRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry
			.requestMatchers(pathPattern(HttpMethod.GET, "/a.*"));
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(PathPatternRequestMatcher.class);
	}

	@Test
	public void pathPatternWhenPatternParamThenReturnPathPatternRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(pathPattern("/a.*"));
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(PathPatternRequestMatcher.class);
	}

	@Test
	public void dispatcherTypeMatchersWhenHttpMethodAndPatternParamsThenReturnPathPatternRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.dispatcherTypeMatchers(HttpMethod.GET,
				DispatcherType.ASYNC);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(DispatcherTypeRequestMatcher.class);
	}

	@Test
	public void dispatcherMatchersWhenPatternParamThenReturnPathPatternRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.dispatcherTypeMatchers(DispatcherType.INCLUDE);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(DispatcherTypeRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenPatternAndMvcPresentThenReturnPathPatternRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers("/path");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(PathPatternRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenHttpMethodAndPatternAndMvcPresentThenReturnPathPatternRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(HttpMethod.GET, "/path");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(PathPatternRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenHttpMethodAndMvcPresentThenReturnPathPatternRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(HttpMethod.GET);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(PathPatternRequestMatcher.class);
	}

	private static class TestRequestMatcherRegistry extends AbstractRequestMatcherRegistry<List<RequestMatcher>> {

		@Override
		protected List<RequestMatcher> chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			return requestMatchers;
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class MockMvcConfiguration {

	}

	private static final class SingleObjectProvider<T> implements ObjectProvider<T> {

		private final T object;

		private SingleObjectProvider(T object) {
			this.object = object;
		}

		@Override
		public Stream<T> stream() {
			return Stream.of(this.object);
		}

	}

}
