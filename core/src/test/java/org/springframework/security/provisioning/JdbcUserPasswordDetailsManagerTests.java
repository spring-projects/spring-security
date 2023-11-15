/*
 * Copyright 2002-2023 the original author or authors.
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
package org.springframework.security.provisioning;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link JdbcUserPasswordDetailsManager}
 *
 * @author Geir Hedemark
 */
public class JdbcUserPasswordDetailsManagerTests extends JdbcUserDetailsManagerTests {
	@Override
	public JdbcUserDetailsManager makeInstance() {
		return new JdbcUserPasswordDetailsManager();
	}

	@Test
	public void updatePasswordSucceeds() {
		insertJoe();
		UserDetails joe = this.manager.loadUserByUsername("joe");
		UserDetails returnedJoe = ((JdbcUserPasswordDetailsManager) this.manager).updatePassword(joe, "newPassword");
		assertThat(returnedJoe.getPassword()).isEqualTo("newPassword");
		UserDetails newJoe = this.manager.loadUserByUsername("joe");
		assertThat(newJoe.getPassword()).isEqualTo("newPassword");
		assertThat(this.cache.getUserMap().containsKey("joe")).isFalse();
	}
}
