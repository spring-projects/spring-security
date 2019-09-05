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

import io.rsocket.Payload;
import io.rsocket.metadata.WellKnownMimeType;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.MediaType;
import org.springframework.messaging.rsocket.MetadataExtractor;
import org.springframework.security.rsocket.DefaultPayloadExchange;
import org.springframework.security.rsocket.PayloadExchange;
import org.springframework.security.rsocket.PayloadExchangeType;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.RouteMatcher;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class RoutePayloadExchangeMatcherTests {
	static final MimeType COMPOSITE_METADATA = MimeTypeUtils.parseMimeType(
			WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());

	@Mock
	private MetadataExtractor metadataExtractor;

	@Mock
	private RouteMatcher routeMatcher;

	private PayloadExchange exchange;

	@Mock
	private Payload payload;

	@Mock
	private RouteMatcher.Route route;

	private String pattern;

	private RoutePayloadExchangeMatcher matcher;

	@Before
	public void setup() {
		this.pattern = "a.b";
		this.matcher = new RoutePayloadExchangeMatcher(this.metadataExtractor, this.routeMatcher, this.pattern);
		this.exchange = new DefaultPayloadExchange(PayloadExchangeType.REQUEST_CHANNEL, this.payload, COMPOSITE_METADATA,
				MediaType.APPLICATION_JSON);
	}

	@Test
	public void matchesWhenNoRouteThenNotMatch() {
		when(this.metadataExtractor.extract(any(), any()))
				.thenReturn(Collections.emptyMap());
		PayloadExchangeMatcher.MatchResult result = this.matcher.matches(this.exchange).block();
		assertThat(result.isMatch()).isFalse();
	}

	@Test
	public void matchesWhenNotMatchThenNotMatch() {
		String route = "route";
		when(this.metadataExtractor.extract(any(), any()))
				.thenReturn(Collections.singletonMap(MetadataExtractor.ROUTE_KEY, route));
		PayloadExchangeMatcher.MatchResult result = this.matcher.matches(this.exchange).block();
		assertThat(result.isMatch()).isFalse();
	}

	@Test
	public void matchesWhenMatchAndNoVariablesThenMatch() {
		String route = "route";
		when(this.metadataExtractor.extract(any(), any()))
				.thenReturn(Collections.singletonMap(MetadataExtractor.ROUTE_KEY, route));
		when(this.routeMatcher.parseRoute(any())).thenReturn(this.route);
		when(this.routeMatcher.matchAndExtract(any(), any())).thenReturn(Collections.emptyMap());
		PayloadExchangeMatcher.MatchResult result = this.matcher.matches(this.exchange).block();
		assertThat(result.isMatch()).isTrue();
	}

	@Test
	public void matchesWhenMatchAndVariablesThenMatchAndVariables() {
		String route = "route";
		Map<String, String> variables = Collections.singletonMap("a", "b");
		when(this.metadataExtractor.extract(any(), any()))
				.thenReturn(Collections.singletonMap(MetadataExtractor.ROUTE_KEY, route));
		when(this.routeMatcher.parseRoute(any())).thenReturn(this.route);
		when(this.routeMatcher.matchAndExtract(any(), any())).thenReturn(variables);
		PayloadExchangeMatcher.MatchResult result = this.matcher.matches(this.exchange).block();
		assertThat(result.isMatch()).isTrue();
		assertThat(result.getVariables()).containsAllEntriesOf(variables);
	}
}
