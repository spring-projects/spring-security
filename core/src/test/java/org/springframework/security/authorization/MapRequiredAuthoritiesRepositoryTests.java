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

package org.springframework.security.authorization;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthorities;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Test {@link MapRequiredAuthoritiesRepository}.
 *
 * @author Rob Winch
 * @since 7.0
 */
class MapRequiredAuthoritiesRepositoryTests {

	private MapRequiredAuthoritiesRepository repository = new MapRequiredAuthoritiesRepository();

	private String username = "user";

	private List<String> authorities = List.of(GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY,
			GrantedAuthorities.FACTOR_OTT_AUTHORITY);

	@Test
	void workflow() {
		this.repository.saveRequiredAuthorities(this.username, this.authorities);
		assertThat(this.repository.findRequiredAuthorities(this.username))
			.containsExactlyInAnyOrderElementsOf(this.authorities);
		List<String> otherAuthorities = List.of(GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY,
				GrantedAuthorities.FACTOR_WEBAUTHN_AUTHORITY);
		this.repository.saveRequiredAuthorities(this.username, otherAuthorities);
		assertThat(this.repository.findRequiredAuthorities(this.username))
			.containsExactlyInAnyOrderElementsOf(otherAuthorities);
		this.repository.deleteRequiredAuthorities(this.username);
		assertThat(this.repository.findRequiredAuthorities(this.username)).isEmpty();
	}

	@Test
	void findRequiredAuthoritiesWhenNullUsernameThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.findRequiredAuthorities(null));
	}

	@Test
	void findRequiredAuthoritiesWhenEmptyUsernameThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.findRequiredAuthorities(""));
	}

	@Test
	void saveRequiredAuthoritiesWhenNullUsernameThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.repository.saveRequiredAuthorities(null, this.authorities));
	}

	@Test
	void saveRequiredAuthoritiesWhenEmptyUsernameThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.repository.saveRequiredAuthorities("", this.authorities));
	}

	@Test
	void saveRequiredAuthoritiesWhenNullAuthoritiesThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.repository.saveRequiredAuthorities(this.username, null));
	}

	@Test
	void deleteRequiredAuthoritiesWhenNullUsernameThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.deleteRequiredAuthorities(null));
	}

	@Test
	void deleteRequiredAuthoritiesWhenEmptyUsernameThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.deleteRequiredAuthorities(""));
	}

}
