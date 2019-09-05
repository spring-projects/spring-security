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

package org.springframework.security.rsocket.util;

import org.springframework.security.rsocket.interceptor.PayloadExchange;

import java.util.Collections;
import java.util.Map;

/**
 * @author Rob Winch
 * @since 5.2
 */
public class PayloadExchangeAuthorizationContext {
	private final PayloadExchange exchange;
	private final Map<String, Object> variables;

	public PayloadExchangeAuthorizationContext(PayloadExchange exchange) {
		this(exchange, Collections.emptyMap());
	}

	public PayloadExchangeAuthorizationContext(PayloadExchange exchange, Map<String, Object> variables) {
		this.exchange = exchange;
		this.variables = variables;
	}

	public PayloadExchange getExchange() {
		return this.exchange;
	}

	public Map<String, Object> getVariables() {
		return Collections.unmodifiableMap(this.variables);
	}
}
