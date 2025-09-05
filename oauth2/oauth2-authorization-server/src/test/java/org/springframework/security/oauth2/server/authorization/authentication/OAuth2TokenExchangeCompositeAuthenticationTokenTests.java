/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2TokenExchangeCompositeAuthenticationToken}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2TokenExchangeCompositeAuthenticationTokenTests {

	@Test
	public void constructorWhenSubjectNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2TokenExchangeCompositeAuthenticationToken(null, null))
				.withMessage("subject cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenActorsNullThenThrowIllegalArgumentException() {
		TestingAuthenticationToken subject = new TestingAuthenticationToken("subject", null);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2TokenExchangeCompositeAuthenticationToken(subject, null))
				.withMessage("actors cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenRequiredParametersProvidedThenCreated() {
		TestingAuthenticationToken subject = new TestingAuthenticationToken("subject", null);
		OAuth2TokenExchangeActor actor1 = new OAuth2TokenExchangeActor(Map.of("claim1", "value1"));
		OAuth2TokenExchangeActor actor2 = new OAuth2TokenExchangeActor(Map.of("claim2", "value2"));
		List<OAuth2TokenExchangeActor> actors = List.of(actor1, actor2);
		OAuth2TokenExchangeCompositeAuthenticationToken authentication = new OAuth2TokenExchangeCompositeAuthenticationToken(
				subject, actors);
		assertThat(authentication.getSubject()).isEqualTo(subject);
		assertThat(authentication.getActors()).isEqualTo(actors);
	}

}
