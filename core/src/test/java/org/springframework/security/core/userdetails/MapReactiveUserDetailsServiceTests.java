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

package org.springframework.security.core.userdetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

public class MapReactiveUserDetailsServiceTests {

	// @formatter:off
	private static final UserDetails USER_DETAILS = User.withUsername("user")
			.password("password")
			.roles("USER")
			.build();
	// @formatter:on
	private MapReactiveUserDetailsService users = new MapReactiveUserDetailsService(Arrays.asList(USER_DETAILS));

	@Test
	public void constructorNullUsers() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new MapReactiveUserDetailsService((Collection<UserDetails>) null));
	}

	@Test
	public void constructorEmptyUsers() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new MapReactiveUserDetailsService(Collections.emptyList()));
	}

	@Test
	public void constructorCaseIntensiveKey() {
		UserDetails userDetails = User.withUsername("USER").password("password").roles("USER").build();
		MapReactiveUserDetailsService userDetailsService = new MapReactiveUserDetailsService(userDetails);
		assertThat(userDetailsService.findByUsername("user").block()).isEqualTo(userDetails);
	}

	@Test
	public void findByUsernameWhenFoundThenReturns() {
		assertThat((this.users.findByUsername(USER_DETAILS.getUsername()).block())).isEqualTo(USER_DETAILS);
	}

	@Test
	public void findByUsernameWhenDifferentCaseThenReturns() {
		assertThat((this.users.findByUsername("uSeR").block())).isEqualTo(USER_DETAILS);
	}

	@Test
	public void findByUsernameWhenClearCredentialsThenFindByUsernameStillHasCredentials() {
		User foundUser = this.users.findByUsername(USER_DETAILS.getUsername()).cast(User.class).block();
		assertThat(foundUser.getPassword()).isNotEmpty();
		foundUser.eraseCredentials();
		assertThat(foundUser.getPassword()).isNull();
		foundUser = this.users.findByUsername(USER_DETAILS.getUsername()).cast(User.class).block();
		assertThat(foundUser.getPassword()).isNotEmpty();
	}

	@Test
	public void findByUsernameWhenNotFoundThenEmpty() {
		assertThat((this.users.findByUsername("notfound"))).isEqualTo(Mono.empty());
	}

	@Test
	public void updatePassword() {
		this.users.updatePassword(USER_DETAILS, "new").block();
		assertThat(this.users.findByUsername(USER_DETAILS.getUsername()).block().getPassword()).isEqualTo("new");
	}

}
