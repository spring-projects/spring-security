/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package  org.springframework.security.web.server.header;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 *
 * @author Rob Winch
 * @since 5.0
 */
public class CompositeHttpHeadersWriter implements HttpHeadersWriter {
	private final List<HttpHeadersWriter> writers;

	public CompositeHttpHeadersWriter(HttpHeadersWriter... writers) {
		this(Arrays.asList(writers));
	}

	public CompositeHttpHeadersWriter(List<HttpHeadersWriter> writers) {
		this.writers = writers;
	}

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		Stream<Mono<Void>> results = writers.stream().map( writer -> writer.writeHttpHeaders(exchange));
		return Mono.when(results.collect(Collectors.toList()));
	}

}
