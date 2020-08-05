/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.util.matcher;

import java.util.Map;
import java.util.Optional;

import reactor.core.publisher.Mono;

import org.springframework.messaging.rsocket.MetadataExtractor;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.util.Assert;
import org.springframework.util.RouteMatcher;

/**
 * FIXME: Pay attention to the package this goes into. It requires spring-messaging for
 * the MetadataExtractor.
 *
 * @author Rob Winch
 * @since 5.2
 */
public class RoutePayloadExchangeMatcher implements PayloadExchangeMatcher {

	private final String pattern;

	private final MetadataExtractor metadataExtractor;

	private final RouteMatcher routeMatcher;

	public RoutePayloadExchangeMatcher(MetadataExtractor metadataExtractor, RouteMatcher routeMatcher, String pattern) {
		Assert.notNull(pattern, "pattern cannot be null");
		this.metadataExtractor = metadataExtractor;
		this.routeMatcher = routeMatcher;
		this.pattern = pattern;
	}

	@Override
	public Mono<MatchResult> matches(PayloadExchange exchange) {
		Map<String, Object> metadata = this.metadataExtractor.extract(exchange.getPayload(),
				exchange.getMetadataMimeType());
		return Optional.ofNullable((String) metadata.get(MetadataExtractor.ROUTE_KEY))
				.map(routeValue -> this.routeMatcher.parseRoute(routeValue))
				.map(route -> this.routeMatcher.matchAndExtract(this.pattern, route)).map(v -> MatchResult.match(v))
				.orElse(MatchResult.notMatch());
	}

}
