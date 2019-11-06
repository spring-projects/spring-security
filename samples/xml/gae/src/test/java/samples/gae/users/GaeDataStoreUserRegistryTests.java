/*
 * Copyright 2002-2016 the original author or authors.
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
package samples.gae.users;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.EnumSet;
import java.util.Set;

import com.google.appengine.tools.development.testing.LocalDatastoreServiceTestConfig;
import com.google.appengine.tools.development.testing.LocalServiceTestHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import samples.gae.security.AppRole;

/**
 * @author Luke Taylor
 */
public class GaeDataStoreUserRegistryTests {
	private final LocalServiceTestHelper helper = new LocalServiceTestHelper(
			new LocalDatastoreServiceTestConfig());

	@Before
	public void setUp() {
		helper.setUp();
	}

	@After
	public void tearDown() {
		helper.tearDown();
	}

	@Test
	public void correctDataIsRetrievedAfterInsert() {
		GaeDatastoreUserRegistry registry = new GaeDatastoreUserRegistry();

		Set<AppRole> roles = EnumSet.of(AppRole.ADMIN, AppRole.USER);
		String userId = "someUserId";

		GaeUser origUser = new GaeUser(userId, "nick", "nick@blah.com", "Forename",
				"Surname", roles, true);

		registry.registerUser(origUser);

		GaeUser loadedUser = registry.findUser(userId);

		assertThat(origUser.getUserId()).isEqualTo(loadedUser.getUserId());
		assertThat(loadedUser.isEnabled()).isEqualTo(true);
		assertThat(loadedUser.getAuthorities()).isEqualTo(roles);
		assertThat(loadedUser.getNickname()).isEqualTo("nick");
		assertThat(loadedUser.getEmail()).isEqualTo("nick@blah.com");
		assertThat(loadedUser.getForename()).isEqualTo("Forename");
		assertThat(loadedUser.getSurname()).isEqualTo("Surname");
	}
}
