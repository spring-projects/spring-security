/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.web.util.matcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.context.request.NativeWebRequest;

/**
 * @author Rob Winch
 * @author Dan Zheng
 */
@RunWith(MockitoJUnitRunner.class)
public class MediaTypeRequestMatcherTests {
	private MediaTypeRequestMatcher matcher;
	private MockHttpServletRequest request;

	@Mock
	private ContentNegotiationStrategy negotiationStrategy;

	@Before
	public void setup() {
		request = new MockHttpServletRequest();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenNullCNSThenIAE() {
		ContentNegotiationStrategy c = null;
		new MediaTypeRequestMatcher(c, MediaType.ALL);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullCNSSet() {
		new MediaTypeRequestMatcher(null, Collections.singleton(MediaType.ALL));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNoVarargs() {
		new MediaTypeRequestMatcher(negotiationStrategy);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullMediaTypes() {
		Collection<MediaType> mediaTypes = null;
		new MediaTypeRequestMatcher(negotiationStrategy, mediaTypes);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmtpyMediaTypes() {
		new MediaTypeRequestMatcher(negotiationStrategy,
				Collections.<MediaType> emptyList());
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenEmptyMediaTypeThenIAE() {
		new MediaTypeRequestMatcher();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenEmptyMediaTypeCollectionThenIAE() {
		new MediaTypeRequestMatcher(Collections.<MediaType> emptyList());
	}

	@Test
	public void negotiationStrategyThrowsHMTNAE()
			throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenThrow(new HttpMediaTypeNotAcceptableException("oops"));

		matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.ALL);
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void mediaAllMatches() throws Exception {

		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.ALL));

		matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_HTML);
		assertThat(matcher.matches(request)).isTrue();

		matcher = new MediaTypeRequestMatcher(negotiationStrategy,
				MediaType.APPLICATION_XHTML_XML);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderAsteriskThenAll() throws Exception {
		request.addHeader("Accept", "*/*");
		matcher = new MediaTypeRequestMatcher(MediaType.ALL);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderAsteriskThenAnyone() throws Exception {
		request.addHeader("Accept", "*/*");
		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderAsteriskThenAllInCollection() throws Exception {
		request.addHeader("Accept", "*/*");
		matcher = new MediaTypeRequestMatcher(Collections.singleton(MediaType.ALL));
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderAsteriskThenAnyoneInCollection() throws Exception {
		request.addHeader("Accept", "*/*");
		matcher = new MediaTypeRequestMatcher(Collections.singleton(MediaType.TEXT_HTML));
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenNoAcceptHeaderThenAll() throws Exception {
		request.removeHeader("Accept");
		// if not set Accept, it is match all
		matcher = new MediaTypeRequestMatcher(MediaType.ALL);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenNoAcceptHeaderThenAnyone() throws Exception {
		request.removeHeader("Accept");
		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenSingleAcceptHeaderThenOne() throws Exception {
		request.addHeader("Accept", "text/html");
		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenSingleAcceptHeaderThenOneWithCollection() throws Exception {
		request.addHeader("Accept", "text/html");
		matcher = new MediaTypeRequestMatcher(Collections.singleton(MediaType.TEXT_HTML));
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenMultipleAcceptHeaderThenMatchMultiple() throws Exception {
		request.addHeader("Accept", "text/html, application/xhtml+xml, application/xml;q=0.9");
		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenMultipleAcceptHeaderThenAnyoneInCollection() throws Exception {
		request.addHeader("Accept", "text/html, application/xhtml+xml, application/xml;q=0.9");
		matcher = new MediaTypeRequestMatcher(Arrays.asList(MediaType.APPLICATION_XHTML_XML));
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void multipleMediaType() throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(
						Arrays.asList(MediaType.TEXT_PLAIN,
								MediaType.APPLICATION_XHTML_XML, MediaType.TEXT_HTML));

		matcher = new MediaTypeRequestMatcher(negotiationStrategy,
				MediaType.APPLICATION_ATOM_XML, MediaType.TEXT_HTML);
		assertThat(matcher.matches(request)).isTrue();

		matcher = new MediaTypeRequestMatcher(negotiationStrategy,
				MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_JSON);
		assertThat(matcher.matches(request)).isTrue();

		matcher = new MediaTypeRequestMatcher(negotiationStrategy,
				MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void resolveTextPlainMatchesTextAll()
			throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.TEXT_PLAIN));

		matcher = new MediaTypeRequestMatcher(negotiationStrategy, new MediaType("text",
				"*"));
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderIsTextThenMediaTypeAllIsMatched() {
		request.addHeader("Accept", MediaType.TEXT_PLAIN_VALUE);

		matcher = new MediaTypeRequestMatcher(new MediaType("text", "*"));
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void resolveTextAllMatchesTextPlain()
			throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(new MediaType("text", "*")));

		matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_PLAIN);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderIsTextWildcardThenMediaTypeTextIsMatched() {
		request.addHeader("Accept", "text/*");

		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_PLAIN);
		assertThat(matcher.matches(request)).isTrue();
	}


	// useEquals

	@Test
	public void useEqualsResolveTextAllMatchesTextPlain()
			throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(new MediaType("text", "*")));

		matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_PLAIN);
		matcher.setUseEquals(true);
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void useEqualsWhenTrueThenMediaTypeTextIsNotMatched() {
		request.addHeader("Accept", "text/*");

		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_PLAIN);
		matcher.setUseEquals(true);
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void useEqualsResolveTextPlainMatchesTextAll()
			throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.TEXT_PLAIN));

		matcher = new MediaTypeRequestMatcher(negotiationStrategy, new MediaType("text",
				"*"));
		matcher.setUseEquals(true);
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void useEqualsWhenTrueThenMediaTypeTextAllIsNotMatched() {
		request.addHeader("Accept", MediaType.TEXT_PLAIN_VALUE);

		matcher = new MediaTypeRequestMatcher(new MediaType("text", "*"));
		matcher.setUseEquals(true);
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void useEqualsSame() throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.TEXT_PLAIN));

		matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_PLAIN);
		matcher.setUseEquals(true);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void useEqualsWhenTrueThenMediaTypeIsMatchedWithEqualString() {
		request.addHeader("Accept", MediaType.TEXT_PLAIN_VALUE);

		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_PLAIN);
		matcher.setUseEquals(true);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void useEqualsWithCustomMediaType() throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(new MediaType("text", "unique")));

		matcher = new MediaTypeRequestMatcher(negotiationStrategy, new MediaType("text",
				"unique"));
		matcher.setUseEquals(true);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void useEqualsWhenTrueThenCustomMediaTypeIsMatched() {
		request.addHeader("Accept", "text/unique");

		matcher = new MediaTypeRequestMatcher(new MediaType("text", "unique"));
		matcher.setUseEquals(true);
		assertThat(matcher.matches(request)).isTrue();
	}

	// ignoreMediaTypeAll

	@Test
	public void mediaAllIgnoreMediaTypeAll() throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.ALL));
		matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_HTML);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void ignoredMediaTypesWhenAllThenAnyoneIsNotMatched() {
		request.addHeader("Accept", MediaType.ALL_VALUE);
		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void mediaAllAndTextHtmlIgnoreMediaTypeAll()
			throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.ALL, MediaType.TEXT_HTML));
		matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_HTML);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void ignoredMediaTypesWhenAllAndTextThenTextCanBeMatched() {
		request.addHeader("Accept", MediaType.ALL_VALUE + ", " + MediaType.TEXT_HTML_VALUE);
		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void mediaAllQ08AndTextPlainIgnoreMediaTypeAll()
			throws HttpMediaTypeNotAcceptableException {
		when(negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(
						Arrays.asList(MediaType.TEXT_PLAIN,
								MediaType.parseMediaType("*/*;q=0.8")));
		matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_HTML);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void ignoredMediaTypesWhenAllThenQ08WithTextIsNotMatched() {
		request.addHeader("Accept", MediaType.TEXT_PLAIN + ", */*;q=0.8");
		matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(matcher.matches(request)).isFalse();
	}
}
