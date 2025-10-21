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

package org.springframework.security.access;

import org.junit.jupiter.api.Test;

import org.springframework.security.access.event.AuthorizedEvent;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.util.SimpleMethodInvocation;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link AuthorizedEvent}.
 *
 * @author Ben Alex
 */
public class AuthorizedEventTests {

	@Test
	public void testRejectsNulls() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AuthorizedEvent(null,
				SecurityConfig.createList("TEST"), UsernamePasswordAuthenticationToken.unauthenticated("foo", "bar")));
	}

	@Test
	public void testRejectsNulls2() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AuthorizedEvent(new SimpleMethodInvocation(), null,
				UsernamePasswordAuthenticationToken.unauthenticated("foo", "bar")));
	}

	@Test
	public void testRejectsNulls3() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new AuthorizedEvent(new SimpleMethodInvocation(), SecurityConfig.createList("TEST"), null));
	}

}
