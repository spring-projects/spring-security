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

package org.springframework.security.web.server.ui;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import reactor.core.publisher.Mono;

import org.springframework.core.ResolvableType;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ResourceHttpMessageWriter;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * Serve common static assets used in default UIs, such as CSS or Javascript files. For
 * internal use only.
 *
 * @author Daniel Garnier-Moiroux
 * @since 6.4
 */
public final class DefaultResourcesWebFilter implements WebFilter {

	private final ServerWebExchangeMatcher matcher;

	private final ClassPathResource resource;

	private final MediaType mediaType;

	private DefaultResourcesWebFilter(ServerWebExchangeMatcher matcher, ClassPathResource resource,
			MediaType mediaType) {
		Assert.isTrue(resource.exists(), "classpath resource must exist");
		this.matcher = matcher;
		this.resource = resource;
		this.mediaType = mediaType;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.matcher.matches(exchange)
			.filter(ServerWebExchangeMatcher.MatchResult::isMatch)
			.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
			.flatMap((matchResult) -> sendContent(exchange));
	}

	private Mono<Void> sendContent(ServerWebExchange exchange) {
		exchange.getResponse().setStatusCode(HttpStatus.OK);
		ResourceHttpMessageWriter writer = new ResourceHttpMessageWriter();
		return writer.write(Mono.just(this.resource), ResolvableType.forClass(Resource.class),
				ResolvableType.forClass(Resource.class), this.mediaType, exchange.getRequest(), exchange.getResponse(),
				Collections.emptyMap());
	}

	@Override
	public String toString() {
		return "%s{matcher=%s, resource='%s'}".formatted(getClass().getSimpleName(), this.matcher,
				this.resource.getPath());
	}

	/**
	 * Create an instance of {@link DefaultResourcesWebFilter} serving Spring Security's
	 * default CSS stylesheet.
	 * <p>
	 * The created {@link DefaultResourcesFilter} matches requests
	 * {@code HTTP GET /default-ui.css}, and returns the default stylesheet at
	 * {@code org/springframework/security/default-ui.css} with content-type
	 * {@code text/css;charset=UTF-8}.
	 * @return -
	 */
	public static DefaultResourcesWebFilter css() {
		return new DefaultResourcesWebFilter(
				new PathPatternParserServerWebExchangeMatcher("/default-ui.css", HttpMethod.GET),
				new ClassPathResource("org/springframework/security/default-ui.css"),
				new MediaType("text", "css", StandardCharsets.UTF_8));
	}

}
