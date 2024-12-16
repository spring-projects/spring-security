/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.server.authentication.ott;

import java.util.List;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

/**
 * An implementation of {@link ServerAuthenticationConverter} for resolving
 * {@link OneTimeTokenAuthenticationToken} from token parameter.
 *
 * @author Max Batischev
 * @since 6.4
 * @see GenerateOneTimeTokenWebFilter
 */
public final class ServerOneTimeTokenAuthenticationConverter implements ServerAuthenticationConverter {

	private static final String TOKEN = "token";

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		Assert.notNull(exchange, "exchange cannot be null");
		if (isFormEncodedRequest(exchange.getRequest())) {
			return exchange.getFormData()
				.map((data) -> OneTimeTokenAuthenticationToken.unauthenticated(data.getFirst(TOKEN)));
		}
		String token = resolveTokenFromRequest(exchange.getRequest());
		if (!StringUtils.hasText(token)) {
			return Mono.empty();
		}
		return Mono.just(OneTimeTokenAuthenticationToken.unauthenticated(token));
	}

	private String resolveTokenFromRequest(ServerHttpRequest request) {
		List<String> parameterTokens = request.getQueryParams().get(TOKEN);
		if (CollectionUtils.isEmpty(parameterTokens)) {
			return null;
		}
		if (parameterTokens.size() == 1) {
			return parameterTokens.get(0);
		}
		return null;
	}

	private boolean isFormEncodedRequest(ServerHttpRequest request) {
		return HttpMethod.POST.equals(request.getMethod()) && MediaType.APPLICATION_FORM_URLENCODED_VALUE
			.equals(request.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE));
	}

}
