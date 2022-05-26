/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation;

import org.mockito.ArgumentMatcher;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextChangedEvent;

import static org.mockito.ArgumentMatchers.argThat;

public final class SecurityContextChangedListenerArgumentMatchers {

	public static SecurityContextChangedEvent setAuthentication(Class<? extends Authentication> authenticationClass) {
		return argThat(new ArgumentMatcher<SecurityContextChangedEvent>() {
			public boolean matches(SecurityContextChangedEvent event) {
				Authentication previous = authentication(event.getOldContext());
				Authentication next = authentication(event.getNewContext());
				return previous == null && next != null && authenticationClass.isAssignableFrom(next.getClass());
			}

			public String toString() {
				return "authentication set to " + authenticationClass;
			}
		});
	}

	private static Authentication authentication(SecurityContext context) {
		if (context == null) {
			return null;
		}
		return context.getAuthentication();
	}

	private SecurityContextChangedListenerArgumentMatchers() {

	}

}
