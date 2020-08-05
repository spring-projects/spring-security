/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.reactive.result.view;

import java.util.Collections;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.lang.NonNull;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.reactive.result.view.RequestDataValueProcessor;
import org.springframework.web.server.ServerWebExchange;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class CsrfRequestDataValueProcessor implements RequestDataValueProcessor {

	/**
	 * The default request attribute to look for a {@link CsrfToken}.
	 */
	public static final String DEFAULT_CSRF_ATTR_NAME = "_csrf";

	private static final Pattern DISABLE_CSRF_TOKEN_PATTERN = Pattern.compile("(?i)^(GET|HEAD|TRACE|OPTIONS)$");

	private static final String DISABLE_CSRF_TOKEN_ATTR = "DISABLE_CSRF_TOKEN_ATTR";

	@Override
	public String processAction(ServerWebExchange exchange, String action, String httpMethod) {
		if (httpMethod != null && DISABLE_CSRF_TOKEN_PATTERN.matcher(httpMethod).matches()) {
			exchange.getAttributes().put(DISABLE_CSRF_TOKEN_ATTR, Boolean.TRUE);
		}
		else {
			exchange.getAttributes().remove(DISABLE_CSRF_TOKEN_ATTR);
		}
		return action;
	}

	@Override
	public String processFormFieldValue(ServerWebExchange exchange, String name, String value, String type) {
		return value;
	}

	@NonNull
	@Override
	public Map<String, String> getExtraHiddenFields(ServerWebExchange exchange) {
		if (Boolean.TRUE.equals(exchange.getAttribute(DISABLE_CSRF_TOKEN_ATTR))) {
			exchange.getAttributes().remove(DISABLE_CSRF_TOKEN_ATTR);
			return Collections.emptyMap();
		}
		CsrfToken token = exchange.getAttribute(DEFAULT_CSRF_ATTR_NAME);
		if (token == null) {
			return Collections.emptyMap();
		}
		return Collections.singletonMap(token.getParameterName(), token.getToken());
	}

	@Override
	public String processUrl(ServerWebExchange exchange, String url) {
		return url;
	}

}
