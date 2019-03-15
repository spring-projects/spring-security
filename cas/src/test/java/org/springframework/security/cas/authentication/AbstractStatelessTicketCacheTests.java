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
package org.springframework.security.cas.authentication;

import java.util.ArrayList;
import java.util.List;

import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

/**
 *
 * @author Scott Battaglia
 * @since 2.0
 *
 */
public abstract class AbstractStatelessTicketCacheTests {

	protected CasAuthenticationToken getToken() {
		List<String> proxyList = new ArrayList<>();
		proxyList.add("https://localhost/newPortal/login/cas");

		User user = new User("rod", "password", true, true, true, true,
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
		final Assertion assertion = new AssertionImpl("rod");

		return new CasAuthenticationToken("key", user, "ST-0-ER94xMJmn6pha35CQRoZ",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"), user,
				assertion);
	}

}
