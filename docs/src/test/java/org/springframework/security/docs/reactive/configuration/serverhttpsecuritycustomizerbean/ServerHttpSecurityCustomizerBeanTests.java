/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.docs.reactive.configuration.serverhttpsecuritycustomizerbean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class ServerHttpSecurityCustomizerBeanTests {
	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private WebTestClient webTest;

	@Test
	void httpSecurityCustomizer() throws Exception {
		this.spring.register(
				ServerHttpSecurityCustomizerBeanConfiguration.class).autowire();
		// @formatter:off
		this.webTest
			.get()
			.uri("http://localhost/")
			.exchange()
			.expectHeader().location("https://localhost/")
			.expectHeader()
				.value("Content-Security-Policy", csp ->
					assertThat(csp).isEqualTo("object-src 'none'")
				);
		// @formatter:on
	}

}
