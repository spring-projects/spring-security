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

package org.springframework.security.web.server.context;

import org.junit.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class ServerWebExchangeAttributeSecurityContextServerRepositoryTests {
	ServerWebExchangeAttributeSecurityContextServerRepository repository = new ServerWebExchangeAttributeSecurityContextServerRepository();
	ServerWebExchange exchange = MockServerHttpRequest.get("/").toExchange();

	@Test
	public void saveAndLoad() {
		SecurityContext context = new SecurityContextImpl();
		this.repository.save(this.exchange, context).block();

		Mono<SecurityContext> loaded = this.repository.load(this.exchange);

		assertThat(context).isSameAs(loaded.block());
	}

}
