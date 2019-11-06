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
package samples.gae.security;

import static org.assertj.core.api.Assertions.*;
import static samples.gae.security.AppRole.*;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author Luke Taylor
 */
public class AppRoleTests {

	@Test
	public void getAuthorityReturnsRoleName() {
		GrantedAuthority admin = ADMIN;

		assertThat(admin.getAuthority()).isEqualTo("ROLE_ADMIN");
	}

	@Test
	public void bitsAreCorrect() {
		// If this fails, someone has modified the Enum and the Datastore is probably
		// corrupt!
		assertThat(ADMIN.getBit()).isZero();
		assertThat(NEW_USER.getBit()).isEqualTo(1);
		assertThat(USER.getBit()).isEqualTo(2);
	}
}
