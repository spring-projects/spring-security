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

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.util.SimpleMethodInvocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link AuthorizationFailureEvent}.
 *
 * @author Ben Alex
 */
public class AuthorizationFailureEventTests {

	private final UsernamePasswordAuthenticationToken foo = UsernamePasswordAuthenticationToken.unauthenticated("foo",
			"bar");

	private List<ConfigAttribute> attributes = SecurityConfig.createList("TEST");

	private AccessDeniedException exception = new AuthorizationServiceException("error", new Throwable());

	@Test
	public void rejectsNullSecureObject() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new AuthorizationFailureEvent(null, this.attributes, this.foo, this.exception));
	}

	@Test
	public void rejectsNullAttributesList() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new AuthorizationFailureEvent(new SimpleMethodInvocation(), null, this.foo, this.exception));
	}

	@Test
	public void rejectsNullAuthentication() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new AuthorizationFailureEvent(new SimpleMethodInvocation(), this.attributes, null,
					this.exception));
	}

	@Test
	public void rejectsNullException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new AuthorizationFailureEvent(new SimpleMethodInvocation(), this.attributes, this.foo, null));
	}

	@Test
	public void gettersReturnCtorSuppliedData() {
		AuthorizationFailureEvent event = new AuthorizationFailureEvent(new Object(), this.attributes, this.foo,
				this.exception);
		assertThat(event.getConfigAttributes()).isSameAs(this.attributes);
		assertThat(event.getAccessDeniedException()).isSameAs(this.exception);
		assertThat(event.getAuthentication()).isSameAs(this.foo);
	}

}
