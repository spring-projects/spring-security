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

package org.springframework.security.web.server.context;

import org.junit.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.server.WebSession;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class WebSessionServerSecurityContextRepositoryTests {

	private MockServerWebExchange exchange = MockServerWebExchange.from(
		MockServerHttpRequest.get("/"));

	private WebSessionServerSecurityContextRepository repository = new WebSessionServerSecurityContextRepository();

	@Test
	public void saveAndLoadWhenDefaultsThenFound() {
		SecurityContext expected = new SecurityContextImpl();
		this.repository.save(this.exchange, expected).block();

		SecurityContext actual = this.repository.load(this.exchange).block();

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	public void saveAndLoadWhenCustomAttributeThenFound() {
		String attrName = "attr";
		this.repository.setSpringSecurityContextAttrName(attrName);
		SecurityContext expected = new SecurityContextImpl();

		this.repository.save(this.exchange, expected).block();

		WebSession session = this.exchange.getSession().block();
		assertThat(session.<SecurityContext>getAttribute(attrName)).isEqualTo(expected);

		SecurityContext actual = this.repository.load(this.exchange).block();

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	public void saveAndLoadWhenNullThenDeletes() {
		SecurityContext context = new SecurityContextImpl();
		this.repository.save(this.exchange, context).block();
		this.repository.save(this.exchange, null).block();

		SecurityContext actual = this.repository.load(this.exchange).block();

		assertThat(actual).isNull();
	}

	@Test
	public void saveWhenNewContextThenChangeSessionId() {
		String originalSessionId = this.exchange.getSession().block().getId();
		this.repository.save(this.exchange, new SecurityContextImpl()).block();
		WebSession session = this.exchange.getSession().block();
		assertThat(session.getId()).isNotEqualTo(originalSessionId);
	}

	@Test
	public void loadWhenNullThenNull() {
		SecurityContext context = this.repository.load(this.exchange).block();
		assertThat(context).isNull();
	}
}
