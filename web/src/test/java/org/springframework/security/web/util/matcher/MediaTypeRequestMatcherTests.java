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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

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
		this.request = new MockHttpServletRequest();
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
		new MediaTypeRequestMatcher(this.negotiationStrategy);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullMediaTypes() {
		Collection<MediaType> mediaTypes = null;
		new MediaTypeRequestMatcher(this.negotiationStrategy, mediaTypes);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmtpyMediaTypes() {
		new MediaTypeRequestMatcher(this.negotiationStrategy, Collections.<MediaType>emptyList());
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenEmptyMediaTypeThenIAE() {
		new MediaTypeRequestMatcher();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenEmptyMediaTypeCollectionThenIAE() {
		new MediaTypeRequestMatcher(Collections.<MediaType>emptyList());
	}

	@Test
	public void negotiationStrategyThrowsHMTNAE() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenThrow(new HttpMediaTypeNotAcceptableException("oops"));

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.ALL);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void mediaAllMatches() throws Exception {

		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.ALL));

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_HTML);
		assertThat(this.matcher.matches(this.request)).isTrue();

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.APPLICATION_XHTML_XML);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderAsteriskThenAll() {
		this.request.addHeader("Accept", "*/*");
		this.matcher = new MediaTypeRequestMatcher(MediaType.ALL);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderAsteriskThenAnyone() {
		this.request.addHeader("Accept", "*/*");
		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderAsteriskThenAllInCollection() {
		this.request.addHeader("Accept", "*/*");
		this.matcher = new MediaTypeRequestMatcher(Collections.singleton(MediaType.ALL));
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderAsteriskThenAnyoneInCollection() {
		this.request.addHeader("Accept", "*/*");
		this.matcher = new MediaTypeRequestMatcher(Collections.singleton(MediaType.TEXT_HTML));
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenNoAcceptHeaderThenAll() {
		this.request.removeHeader("Accept");
		// if not set Accept, it is match all
		this.matcher = new MediaTypeRequestMatcher(MediaType.ALL);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenNoAcceptHeaderThenAnyone() {
		this.request.removeHeader("Accept");
		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenSingleAcceptHeaderThenOne() {
		this.request.addHeader("Accept", "text/html");
		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenSingleAcceptHeaderThenOneWithCollection() {
		this.request.addHeader("Accept", "text/html");
		this.matcher = new MediaTypeRequestMatcher(Collections.singleton(MediaType.TEXT_HTML));
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenMultipleAcceptHeaderThenMatchMultiple() {
		this.request.addHeader("Accept", "text/html, application/xhtml+xml, application/xml;q=0.9");
		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML,
				MediaType.APPLICATION_XML);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenMultipleAcceptHeaderThenAnyoneInCollection() {
		this.request.addHeader("Accept", "text/html, application/xhtml+xml, application/xml;q=0.9");
		this.matcher = new MediaTypeRequestMatcher(Arrays.asList(MediaType.APPLICATION_XHTML_XML));
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void multipleMediaType() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.TEXT_PLAIN, MediaType.APPLICATION_XHTML_XML, MediaType.TEXT_HTML));

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.APPLICATION_ATOM_XML,
				MediaType.TEXT_HTML);
		assertThat(this.matcher.matches(this.request)).isTrue();

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.APPLICATION_XHTML_XML,
				MediaType.APPLICATION_JSON);
		assertThat(this.matcher.matches(this.request)).isTrue();

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.APPLICATION_FORM_URLENCODED,
				MediaType.APPLICATION_JSON);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void resolveTextPlainMatchesTextAll() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.TEXT_PLAIN));

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, new MediaType("text", "*"));
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderIsTextThenMediaTypeAllIsMatched() {
		this.request.addHeader("Accept", MediaType.TEXT_PLAIN_VALUE);

		this.matcher = new MediaTypeRequestMatcher(new MediaType("text", "*"));
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void resolveTextAllMatchesTextPlain() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(new MediaType("text", "*")));

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_PLAIN);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchWhenAcceptHeaderIsTextWildcardThenMediaTypeTextIsMatched() {
		this.request.addHeader("Accept", "text/*");

		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_PLAIN);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	// useEquals

	@Test
	public void useEqualsResolveTextAllMatchesTextPlain() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(new MediaType("text", "*")));

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_PLAIN);
		this.matcher.setUseEquals(true);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void useEqualsWhenTrueThenMediaTypeTextIsNotMatched() {
		this.request.addHeader("Accept", "text/*");

		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_PLAIN);
		this.matcher.setUseEquals(true);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void useEqualsResolveTextPlainMatchesTextAll() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.TEXT_PLAIN));

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, new MediaType("text", "*"));
		this.matcher.setUseEquals(true);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void useEqualsWhenTrueThenMediaTypeTextAllIsNotMatched() {
		this.request.addHeader("Accept", MediaType.TEXT_PLAIN_VALUE);

		this.matcher = new MediaTypeRequestMatcher(new MediaType("text", "*"));
		this.matcher.setUseEquals(true);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void useEqualsSame() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.TEXT_PLAIN));

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_PLAIN);
		this.matcher.setUseEquals(true);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void useEqualsWhenTrueThenMediaTypeIsMatchedWithEqualString() {
		this.request.addHeader("Accept", MediaType.TEXT_PLAIN_VALUE);

		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_PLAIN);
		this.matcher.setUseEquals(true);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void useEqualsWithCustomMediaType() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(new MediaType("text", "unique")));

		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, new MediaType("text", "unique"));
		this.matcher.setUseEquals(true);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void useEqualsWhenTrueThenCustomMediaTypeIsMatched() {
		this.request.addHeader("Accept", "text/unique");

		this.matcher = new MediaTypeRequestMatcher(new MediaType("text", "unique"));
		this.matcher.setUseEquals(true);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	// ignoreMediaTypeAll

	@Test
	public void mediaAllIgnoreMediaTypeAll() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.ALL));
		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_HTML);
		this.matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void ignoredMediaTypesWhenAllThenAnyoneIsNotMatched() {
		this.request.addHeader("Accept", MediaType.ALL_VALUE);
		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		this.matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void mediaAllAndTextHtmlIgnoreMediaTypeAll() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.ALL, MediaType.TEXT_HTML));
		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_HTML);
		this.matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void ignoredMediaTypesWhenAllAndTextThenTextCanBeMatched() {
		this.request.addHeader("Accept", MediaType.ALL_VALUE + ", " + MediaType.TEXT_HTML_VALUE);
		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		this.matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void mediaAllQ08AndTextPlainIgnoreMediaTypeAll() throws HttpMediaTypeNotAcceptableException {
		when(this.negotiationStrategy.resolveMediaTypes(any(NativeWebRequest.class)))
				.thenReturn(Arrays.asList(MediaType.TEXT_PLAIN, MediaType.parseMediaType("*/*;q=0.8")));
		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_HTML);
		this.matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void ignoredMediaTypesWhenAllThenQ08WithTextIsNotMatched() {
		this.request.addHeader("Accept", MediaType.TEXT_PLAIN + ", */*;q=0.8");
		this.matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		this.matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		assertThat(this.matcher.matches(this.request)).isFalse();
	}

}
