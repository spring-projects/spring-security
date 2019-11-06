/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.oauth2.client;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AuthorizedClientId}.
 *
 * @author Vedran Pavic
 */
public class OAuth2AuthorizedClientIdTests {

	@Test
	public void constructorWhenRegistrationIdNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizedClientId(null, "test-principal"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistrationId cannot be empty");
	}

	@Test
	public void constructorWhenPrincipalNameNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizedClientId("test-client", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("principalName cannot be empty");
	}

	@Test
	public void equalsWhenSameRegistrationIdAndPrincipalThenShouldReturnTrue() {
		OAuth2AuthorizedClientId id1 = new OAuth2AuthorizedClientId("test-client", "test-principal");
		OAuth2AuthorizedClientId id2 = new OAuth2AuthorizedClientId("test-client", "test-principal");
		assertThat(id1.equals(id2)).isTrue();
	}

	@Test
	public void equalsWhenDifferentRegistrationIdAndSamePrincipalThenShouldReturnFalse() {
		OAuth2AuthorizedClientId id1 = new OAuth2AuthorizedClientId("test-client1", "test-principal");
		OAuth2AuthorizedClientId id2 = new OAuth2AuthorizedClientId("test-client2", "test-principal");
		assertThat(id1.equals(id2)).isFalse();
	}

	@Test
	public void equalsWhenSameRegistrationIdAndDifferentPrincipalThenShouldReturnFalse() {
		OAuth2AuthorizedClientId id1 = new OAuth2AuthorizedClientId("test-client", "test-principal1");
		OAuth2AuthorizedClientId id2 = new OAuth2AuthorizedClientId("test-client", "test-principal2");
		assertThat(id1.equals(id2)).isFalse();
	}

	@Test
	public void hashCodeWhenSameRegistrationIdAndPrincipalThenShouldReturnSame() {
		OAuth2AuthorizedClientId id1 = new OAuth2AuthorizedClientId("test-client", "test-principal");
		OAuth2AuthorizedClientId id2 = new OAuth2AuthorizedClientId("test-client", "test-principal");
		assertThat(id1.hashCode()).isEqualTo(id2.hashCode());
	}

	@Test
	public void hashCodeWhenDifferentRegistrationIdAndSamePrincipalThenShouldNotReturnSame() {
		OAuth2AuthorizedClientId id1 = new OAuth2AuthorizedClientId("test-client1", "test-principal");
		OAuth2AuthorizedClientId id2 = new OAuth2AuthorizedClientId("test-client2", "test-principal");
		assertThat(id1.hashCode()).isNotEqualTo(id2.hashCode());
	}

	@Test
	public void hashCodeWhenSameRegistrationIdAndDifferentPrincipalThenShouldNotReturnSame() {
		OAuth2AuthorizedClientId id1 = new OAuth2AuthorizedClientId("test-client", "test-principal1");
		OAuth2AuthorizedClientId id2 = new OAuth2AuthorizedClientId("test-client", "test-principal2");
		assertThat(id1.hashCode()).isNotEqualTo(id2.hashCode());
	}
}
