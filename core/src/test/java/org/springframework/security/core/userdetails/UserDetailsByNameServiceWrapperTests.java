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

package org.springframework.security.core.userdetails;

import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author TSARDD
 * @since 18-okt-2007
 */
@SuppressWarnings("unchecked")
public class UserDetailsByNameServiceWrapperTests {

	@Test
	public final void testAfterPropertiesSet() {
		UserDetailsByNameServiceWrapper svc = new UserDetailsByNameServiceWrapper();
		assertThatIllegalArgumentException().isThrownBy(svc::afterPropertiesSet);
	}

	@Test
	public final void testGetUserDetails() throws Exception {
		UserDetailsByNameServiceWrapper svc = new UserDetailsByNameServiceWrapper();
		final User user = new User("dummy", "dummy", true, true, true, true, AuthorityUtils.NO_AUTHORITIES);
		svc.setUserDetailsService((name) -> {
			if (user != null && user.getUsername().equals(name)) {
				return user;
			}
			else {
				return null;
			}
		});
		svc.afterPropertiesSet();
		UserDetails result1 = svc.loadUserDetails(new TestingAuthenticationToken("dummy", "dummy"));
		assertThat(result1).as("Result doesn't match original user").isEqualTo(user);
		UserDetails result2 = svc.loadUserDetails(new TestingAuthenticationToken("dummy2", "dummy"));
		assertThat(result2).as("Result should have been null").isNull();
	}

}
