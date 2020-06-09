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
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * Allows matching {@link HttpServletRequest} based upon the {@link MediaType}'s resolved
 * from a {@link ContentNegotiationStrategy}.
 *
 * By default, the matching process will perform the following:
 *
 * <ul>
 * <li>The {@link ContentNegotiationStrategy} will resolve the {@link MediaType} 's for
 * the current request</li>
 * <li>Each matchingMediaTypes that was passed into the constructor will be compared
 * against the {@link MediaType} instances resolved from the
 * {@link ContentNegotiationStrategy}.</li>
 * <li>If one of the matchingMediaTypes is compatible with one of the resolved
 * {@link MediaType} returned from the {@link ContentNegotiationStrategy}, then it returns
 * true</li>
 * </ul>
 *
 * For example, consider the following example
 *
 * <pre>
 * GET /
 * Accept: application/json
 *
 * ContentNegotiationStrategy negotiationStrategy = new HeaderContentNegotiationStrategy()
 * MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
 * assert matcher.matches(request) == true // returns true
 * </pre>
 *
 * The following will also return true
 *
 * <pre>
 * GET /
 * Accept: *&#47;*
 *
 * ContentNegotiationStrategy negotiationStrategy = new HeaderContentNegotiationStrategy()
 * MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
 * assert matcher.matches(request) == true // returns true
 * </pre>
 *
 * <h3>Ignoring Media Types</h3>
 *
 * Sometimes you may want to ignore certain types of media types. For example, you may
 * want to match on "application/json" but ignore "*&#47;" sent by a web browser.
 *
 * <pre>
 * GET /
 * Accept: *&#47;*
 *
 * ContentNegotiationStrategy negotiationStrategy = new HeaderContentNegotiationStrategy()
 * MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
 * matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
 * assert matcher.matches(request) == false // returns false
 * </pre>
 *
 * <pre>
 * GET /
 * Accept: application/json
 *
 * ContentNegotiationStrategy negotiationStrategy = new HeaderContentNegotiationStrategy()
 * MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
 * matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
 * assert matcher.matches(request) == true // returns true
 * </pre>
 *
 * <h3>Exact media type comparison</h3>
 *
 * By default as long as the {@link MediaType} discovered by
 * {@link ContentNegotiationStrategy} returns true for
 * {@link MediaType#isCompatibleWith(MediaType)} on the matchingMediaTypes, the result of
 * the match is true. However, sometimes you may want to perform an exact match. This can
 * be done with the following examples:
 *
 * <pre>
 * GET /
 * Accept: application/json
 *
 * ContentNegotiationStrategy negotiationStrategy = new HeaderContentNegotiationStrategy()
 * MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
 * matcher.setUseEquals(true);
 * assert matcher.matches(request) == true // returns true
 * </pre>
 *
 * <pre>
 * GET /
 * Accept: application/*
 *
 * ContentNegotiationStrategy negotiationStrategy = new HeaderContentNegotiationStrategy()
 * MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
 * matcher.setUseEquals(true);
 * assert matcher.matches(request) == false // returns false
 * </pre>
 *
 * <pre>
 * GET /
 * Accept: *&#47;*
 *
 * ContentNegotiationStrategy negotiationStrategy = new HeaderContentNegotiationStrategy()
 * MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
 * matcher.setUseEquals(true);
 * assert matcher.matches(request) == false // returns false
 * </pre>
 *
 * @author Rob Winch
 * @author Dan Zheng
 * @since 3.2
 */

public final class MediaTypeRequestMatcher implements RequestMatcher {

	private final Log logger = LogFactory.getLog(getClass());

	private final ContentNegotiationStrategy contentNegotiationStrategy;

	private final Collection<MediaType> matchingMediaTypes;

	private boolean useEquals;

	private Set<MediaType> ignoredMediaTypes = Collections.emptySet();

	/**
	 * Creates an instance
	 * @param matchingMediaTypes the {@link MediaType} that will make the http request.
	 * @since 5.2
	 */
	public MediaTypeRequestMatcher(MediaType... matchingMediaTypes) {
		this(new HeaderContentNegotiationStrategy(), Arrays.asList(matchingMediaTypes));
	}

	/**
	 * Creates an instance
	 * @param matchingMediaTypes the {@link MediaType} that will make the http request.
	 * @since 5.2
	 */
	public MediaTypeRequestMatcher(Collection<MediaType> matchingMediaTypes) {
		this(new HeaderContentNegotiationStrategy(), matchingMediaTypes);
	}

	/**
	 * Creates an instance
	 * @param contentNegotiationStrategy the {@link ContentNegotiationStrategy} to use
	 * @param matchingMediaTypes the {@link MediaType} that will make the
	 * {@link RequestMatcher} return true
	 */
	public MediaTypeRequestMatcher(ContentNegotiationStrategy contentNegotiationStrategy,
			MediaType... matchingMediaTypes) {
		this(contentNegotiationStrategy, Arrays.asList(matchingMediaTypes));
	}

	/**
	 * Creates an instance
	 * @param contentNegotiationStrategy the {@link ContentNegotiationStrategy} to use
	 * @param matchingMediaTypes the {@link MediaType} that will make the
	 * {@link RequestMatcher} return true
	 */
	public MediaTypeRequestMatcher(ContentNegotiationStrategy contentNegotiationStrategy,
			Collection<MediaType> matchingMediaTypes) {
		Assert.notNull(contentNegotiationStrategy, "ContentNegotiationStrategy cannot be null");
		Assert.notEmpty(matchingMediaTypes, "matchingMediaTypes cannot be null or empty");
		this.contentNegotiationStrategy = contentNegotiationStrategy;
		this.matchingMediaTypes = matchingMediaTypes;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		List<MediaType> httpRequestMediaTypes;
		try {
			httpRequestMediaTypes = this.contentNegotiationStrategy.resolveMediaTypes(new ServletWebRequest(request));
		}
		catch (HttpMediaTypeNotAcceptableException ex) {
			this.logger.debug("Failed to match request since failed to parse MediaTypes", ex);
			return false;
		}
		for (MediaType httpRequestMediaType : httpRequestMediaTypes) {
			if (shouldIgnore(httpRequestMediaType)) {
				continue;
			}
			if (this.useEquals) {
				return this.matchingMediaTypes.contains(httpRequestMediaType);
			}
			for (MediaType matchingMediaType : this.matchingMediaTypes) {
				boolean isCompatibleWith = matchingMediaType.isCompatibleWith(httpRequestMediaType);
				if (isCompatibleWith) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean shouldIgnore(MediaType httpRequestMediaType) {
		for (MediaType ignoredMediaType : this.ignoredMediaTypes) {
			if (httpRequestMediaType.includes(ignoredMediaType)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * If set to true, matches on exact {@link MediaType}, else uses
	 * {@link MediaType#isCompatibleWith(MediaType)}.
	 * @param useEquals specify if equals comparison should be used.
	 */
	public void setUseEquals(boolean useEquals) {
		this.useEquals = useEquals;
	}

	/**
	 * Set the {@link MediaType} to ignore from the {@link ContentNegotiationStrategy}.
	 * This is useful if for example, you want to match on
	 * {@link MediaType#APPLICATION_JSON} but want to ignore {@link MediaType#ALL}.
	 * @param ignoredMediaTypes the {@link MediaType}'s to ignore from the
	 * {@link ContentNegotiationStrategy}
	 */
	public void setIgnoredMediaTypes(Set<MediaType> ignoredMediaTypes) {
		this.ignoredMediaTypes = ignoredMediaTypes;
	}

	@Override
	public String toString() {
		return "MediaTypeRequestMatcher [contentNegotiationStrategy=" + this.contentNegotiationStrategy
				+ ", matchingMediaTypes=" + this.matchingMediaTypes + ", useEquals=" + this.useEquals
				+ ", ignoredMediaTypes=" + this.ignoredMediaTypes + "]";
	}

}
