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

package org.springframework.security.web.server.authorization;

import java.util.Collections;
import java.util.Map;

import org.springframework.web.server.ServerWebExchange;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class AuthorizationContext {

	private final ServerWebExchange exchange;

	private final Map<String, Object> variables;

	public AuthorizationContext(ServerWebExchange exchange) {
		this(exchange, Collections.emptyMap());
	}

	public AuthorizationContext(ServerWebExchange exchange, Map<String, Object> variables) {
		this.exchange = exchange;
		this.variables = variables;
	}

	public ServerWebExchange getExchange() {
		return this.exchange;
	}

	public Map<String, Object> getVariables() {
		return Collections.unmodifiableMap(this.variables);
	}

}
