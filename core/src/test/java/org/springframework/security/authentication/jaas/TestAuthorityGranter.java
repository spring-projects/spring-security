/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.authentication.jaas;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Ray Krueger
 */
public class TestAuthorityGranter implements AuthorityGranter {

	@Override
	public Set<String> grant(Principal principal) {
		Set<String> rtnSet = new HashSet<>();

		if (principal.getName().equals("TEST_PRINCIPAL")) {
			rtnSet.add("ROLE_TEST1");
			rtnSet.add("ROLE_TEST2");
		}

		return rtnSet;
	}

}
