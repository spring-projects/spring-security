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

package org.springframework.security.web.server.header;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;

/**
 * @author Ziqin Wang
 * @since 7.1
 */
class NonceGeneratingWebFilterTests {

	private static final String ATTRIBUTE_NAME = "TEST_NONCE_ATTR";

	private static final int MIN_STRENGTH_IN_BYTE = 16;

	@Test
	void attributeShouldBeAddedAndNonceIsLongEnoughBase64ByDefault() {
		ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		WebFilterChain chain = mock();
		given(chain.filter(exchange)).willReturn(Mono.empty());

		WebFilter filter = new NonceGeneratingWebFilter(ATTRIBUTE_NAME);
		StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
		String nonce = exchange.getRequiredAttribute(ATTRIBUTE_NAME);

		assertThat(nonce).isBase64().hasSizeGreaterThanOrEqualTo((int) Math.ceil(4.0 / 3 * MIN_STRENGTH_IN_BYTE));
		then(chain).should().filter(exchange);
	}

	@Test
	void customNonceGeneratorIsUsed() {
		ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		WebFilterChain chain = mock();
		given(chain.filter(exchange)).willReturn(Mono.empty());
		String nonce = KeyGenerators.string().generateKey();
		StringKeyGenerator nonceGenerator = mock();
		given(nonceGenerator.generateKey()).willReturn(nonce);

		WebFilter filter = new NonceGeneratingWebFilter(ATTRIBUTE_NAME, nonceGenerator);
		StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

		assertThat((String) exchange.getRequiredAttribute(ATTRIBUTE_NAME)).isSameAs(nonce);
		then(nonceGenerator).should().generateKey();
	}

	@Test
	void illegalConstructorArgumentsAreRejected() {
		assertThatIllegalArgumentException().isThrownBy(() -> new NonceGeneratingWebFilter(null))
			.withMessage("AttributeName must not be null or empty");
		assertThatIllegalArgumentException().isThrownBy(() -> new NonceGeneratingWebFilter(""))
			.withMessage("AttributeName must not be null or empty");
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new NonceGeneratingWebFilter(null, KeyGenerators.string()))
			.withMessage("AttributeName must not be null or empty");
		assertThatIllegalArgumentException().isThrownBy(() -> new NonceGeneratingWebFilter("", KeyGenerators.string()))
			.withMessage("AttributeName must not be null or empty");
		assertThatIllegalArgumentException().isThrownBy(() -> new NonceGeneratingWebFilter(ATTRIBUTE_NAME, null))
			.withMessage("NonceGenerator must not be null");
	}

}
