/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.server.util.matcher;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.accept.RequestedContentTypeResolver;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class MediaTypeServerWebExchangeMatcherTests {
	@Mock
	private RequestedContentTypeResolver resolver;

	private MediaTypeServerWebExchangeMatcher matcher;

	@Test(expected = IllegalArgumentException.class)
	public void constructorMediaTypeArrayWhenNullThenThrowsIllegalArgumentException() {
		MediaType[] types = null;
		new MediaTypeServerWebExchangeMatcher(types);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorMediaTypeArrayWhenContainsNullThenThrowsIllegalArgumentException() {
		MediaType[] types = { null };
		new MediaTypeServerWebExchangeMatcher(types);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorMediaTypeListWhenNullThenThrowsIllegalArgumentException() {
		List<MediaType> types = null;
		new MediaTypeServerWebExchangeMatcher(types);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorMediaTypeListWhenContainsNullThenThrowsIllegalArgumentException() {
		List<MediaType> types = Collections.singletonList(null);
		new MediaTypeServerWebExchangeMatcher(types);
	}

	@Test
	public void matchWhenDefaultResolverAndAcceptEqualThenMatch() {
		MediaType acceptType = MediaType.TEXT_HTML;
		MediaTypeServerWebExchangeMatcher matcher = new MediaTypeServerWebExchangeMatcher(acceptType);

		assertThat(matcher.matches(exchange(acceptType)).block().isMatch()).isTrue();
	}

	@Test
	public void matchWhenDefaultResolverAndAcceptEqualAndIgnoreThenMatch() {
		MediaType acceptType = MediaType.TEXT_HTML;
		MediaTypeServerWebExchangeMatcher matcher = new MediaTypeServerWebExchangeMatcher(acceptType);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(matcher.matches(exchange(acceptType)).block().isMatch()).isTrue();
	}

	@Test
	public void matchWhenDefaultResolverAndAcceptEqualAndIgnoreThenNotMatch() {
		MediaType acceptType = MediaType.TEXT_HTML;
		MediaTypeServerWebExchangeMatcher matcher = new MediaTypeServerWebExchangeMatcher(acceptType);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(matcher.matches(exchange(MediaType.ALL)).block().isMatch()).isFalse();
	}

	@Test
	public void matchWhenDefaultResolverAndAcceptImpliedThenMatch() {
		MediaTypeServerWebExchangeMatcher matcher = new MediaTypeServerWebExchangeMatcher(MediaType.parseMediaTypes("text/*"));

		assertThat(matcher.matches(exchange(MediaType.TEXT_HTML)).block().isMatch()).isTrue();
	}

	@Test
	public void matchWhenDefaultResolverAndAcceptImpliedAndUseEqualsThenNotMatch() {
		MediaTypeServerWebExchangeMatcher matcher = new MediaTypeServerWebExchangeMatcher(MediaType.ALL);
		matcher.setUseEquals(true);

		assertThat(matcher.matches(exchange(MediaType.TEXT_HTML)).block().isMatch()).isFalse();
	}

	@Test
	public void matchWhenCustomResolverAndAcceptEqualThenMatch() {
		MediaType acceptType = MediaType.TEXT_HTML;
		when(this.resolver.resolveMediaTypes(any())).thenReturn(Arrays.asList(acceptType));
		MediaTypeServerWebExchangeMatcher matcher = new MediaTypeServerWebExchangeMatcher(acceptType);
		matcher.setRequestedContentTypeResolver(this.resolver);

		assertThat(matcher.matches(exchange(acceptType)).block().isMatch()).isTrue();
	}

	@Test
	public void matchWhenCustomResolverAndDifferentAcceptThenNotMatch() {
		MediaType acceptType = MediaType.TEXT_HTML;
		when(this.resolver.resolveMediaTypes(any())).thenReturn(Arrays.asList(acceptType));
		MediaTypeServerWebExchangeMatcher matcher = new MediaTypeServerWebExchangeMatcher(MediaType.APPLICATION_JSON);
		matcher.setRequestedContentTypeResolver(this.resolver);

		assertThat(matcher.matches(exchange(acceptType)).block().isMatch()).isFalse();
	}

	private static ServerWebExchange exchange(MediaType... accept) {
		return MockServerWebExchange.from(MockServerHttpRequest.get("/").accept(accept).build());
	}
}
