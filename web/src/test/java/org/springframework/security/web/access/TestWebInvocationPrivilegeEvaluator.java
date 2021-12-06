/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.web.access;

import org.springframework.security.core.Authentication;

public final class TestWebInvocationPrivilegeEvaluator {

	private static final AlwaysAllowWebInvocationPrivilegeEvaluator ALWAYS_ALLOW = new AlwaysAllowWebInvocationPrivilegeEvaluator();

	private static final AlwaysDenyWebInvocationPrivilegeEvaluator ALWAYS_DENY = new AlwaysDenyWebInvocationPrivilegeEvaluator();

	private TestWebInvocationPrivilegeEvaluator() {
	}

	public static WebInvocationPrivilegeEvaluator alwaysAllow() {
		return ALWAYS_ALLOW;
	}

	public static WebInvocationPrivilegeEvaluator alwaysDeny() {
		return ALWAYS_DENY;
	}

	private static class AlwaysAllowWebInvocationPrivilegeEvaluator implements WebInvocationPrivilegeEvaluator {

		@Override
		public boolean isAllowed(String uri, Authentication authentication) {
			return true;
		}

		@Override
		public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
			return true;
		}

	}

	private static class AlwaysDenyWebInvocationPrivilegeEvaluator implements WebInvocationPrivilegeEvaluator {

		@Override
		public boolean isAllowed(String uri, Authentication authentication) {
			return false;
		}

		@Override
		public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
			return false;
		}

	}

}
