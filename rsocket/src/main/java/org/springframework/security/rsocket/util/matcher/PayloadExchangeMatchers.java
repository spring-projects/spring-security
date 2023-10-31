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

import reactor.core.publisher.Mono;

import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadExchangeType;

/**
 * @author Rob Winch
 */
public final class PayloadExchangeMatchers {

	private PayloadExchangeMatchers() {
	}

	public static PayloadExchangeMatcher setup() {
		return new PayloadExchangeMatcher() {

			@Override
			public Mono<MatchResult> matches(PayloadExchange exchange) {
				return PayloadExchangeType.SETUP.equals(exchange.getType()) ? MatchResult.match()
						: MatchResult.notMatch();
			}

		};
	}

	public static PayloadExchangeMatcher anyRequest() {
		return new PayloadExchangeMatcher() {

			@Override
			public Mono<MatchResult> matches(PayloadExchange exchange) {
				return exchange.getType().isRequest() ? MatchResult.match() : MatchResult.notMatch();
			}

		};
	}

	public static PayloadExchangeMatcher anyExchange() {
		return new PayloadExchangeMatcher() {

			@Override
			public Mono<MatchResult> matches(PayloadExchange exchange) {
				return MatchResult.match();
			}

		};
	}

}
