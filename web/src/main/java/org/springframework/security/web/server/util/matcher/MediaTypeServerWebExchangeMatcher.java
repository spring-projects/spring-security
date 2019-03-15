/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.web.server.util.matcher;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.InvalidMediaTypeException;
import reactor.core.publisher.Mono;

import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.server.NotAcceptableStatusException;
import org.springframework.web.server.ServerWebExchange;

/**
 * Matches based upon the accept headers.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class MediaTypeServerWebExchangeMatcher implements ServerWebExchangeMatcher {
	private final Log logger = LogFactory.getLog(getClass());

	private final Collection<MediaType> matchingMediaTypes;
	private boolean useEquals;
	private Set<MediaType> ignoredMediaTypes = Collections.emptySet();

	/**
	 * Creates a new instance
	 * @param matchingMediaTypes the types to match on
	 */
	public MediaTypeServerWebExchangeMatcher(MediaType... matchingMediaTypes) {
		Assert.notEmpty(matchingMediaTypes, "matchingMediaTypes cannot be null");
		Assert.noNullElements(matchingMediaTypes, "matchingMediaTypes cannot contain null");
		this.matchingMediaTypes = Arrays.asList(matchingMediaTypes);
	}

	/**
	 * Creates a new instance
	 * @param matchingMediaTypes the types to match on
	 */
	public MediaTypeServerWebExchangeMatcher(Collection<MediaType> matchingMediaTypes) {
		Assert.notEmpty(matchingMediaTypes, "matchingMediaTypes cannot be null");
		Assert.isTrue(!matchingMediaTypes.contains(null), () -> "matchingMediaTypes cannot contain null. Got " + matchingMediaTypes);
		this.matchingMediaTypes = matchingMediaTypes;
	}

	@Override
	public Mono<MatchResult> matches(ServerWebExchange exchange) {
		List<MediaType> httpRequestMediaTypes;
		try {
			httpRequestMediaTypes = resolveMediaTypes(exchange);
		}
		catch (NotAcceptableStatusException e) {
			this.logger.debug("Failed to parse MediaTypes, returning false", e);
			return MatchResult.notMatch();
		}
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("httpRequestMediaTypes=" + httpRequestMediaTypes);
		}
		for (MediaType httpRequestMediaType : httpRequestMediaTypes) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Processing " + httpRequestMediaType);
			}
			if (shouldIgnore(httpRequestMediaType)) {
				this.logger.debug("Ignoring");
				continue;
			}
			if (this.useEquals) {
				boolean isEqualTo = this.matchingMediaTypes
					.contains(httpRequestMediaType);
				this.logger.debug("isEqualTo " + isEqualTo);
				return isEqualTo ? MatchResult.match() : MatchResult.notMatch();
			}
			for (MediaType matchingMediaType : this.matchingMediaTypes) {
				boolean isCompatibleWith = matchingMediaType
					.isCompatibleWith(httpRequestMediaType);
				if (this.logger.isDebugEnabled()) {
					this.logger.debug(matchingMediaType + " .isCompatibleWith "
						+ httpRequestMediaType + " = " + isCompatibleWith);
				}
				if (isCompatibleWith) {
					return MatchResult.match();
				}
			}
		}
		this.logger.debug("Did not match any media types");
		return MatchResult.notMatch();
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
	 *
	 * @param useEquals specify if equals comparison should be used.
	 */
	public void setUseEquals(boolean useEquals) {
		this.useEquals = useEquals;
	}

	/**
	 * Set the {@link MediaType} to ignore from the {@link ContentNegotiationStrategy}.
	 * This is useful if for example, you want to match on
	 * {@link MediaType#APPLICATION_JSON} but want to ignore {@link MediaType#ALL}.
	 *
	 * @param ignoredMediaTypes the {@link MediaType}'s to ignore from the
	 * {@link ContentNegotiationStrategy}
	 */
	public void setIgnoredMediaTypes(Set<MediaType> ignoredMediaTypes) {
		this.ignoredMediaTypes = ignoredMediaTypes;
	}

	private List<MediaType> resolveMediaTypes(ServerWebExchange exchange) throws NotAcceptableStatusException {
		try {
			List<MediaType> mediaTypes = exchange.getRequest().getHeaders().getAccept();
			MediaType.sortBySpecificityAndQuality(mediaTypes);
			return mediaTypes;
		}
		catch (InvalidMediaTypeException ex) {
			String value = exchange.getRequest().getHeaders().getFirst("Accept");
			throw new NotAcceptableStatusException(
				"Could not parse 'Accept' header [" + value + "]: " + ex.getMessage());
		}
	}

	@Override
	public String toString() {
		return "MediaTypeRequestMatcher [matchingMediaTypes="
			+ this.matchingMediaTypes + ", useEquals=" + this.useEquals
			+ ", ignoredMediaTypes=" + this.ignoredMediaTypes + "]";
	}
}
