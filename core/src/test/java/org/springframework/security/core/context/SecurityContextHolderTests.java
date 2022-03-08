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

package org.springframework.security.core.context;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link SecurityContextHolder}.
 *
 * @author Ben Alex
 */
public class SecurityContextHolderTests {

	@BeforeEach
	public final void setUp() {
		SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
	}

	@Test
	public void testContextHolderGetterSetterClearer() {
		SecurityContext sc = new SecurityContextImpl();
		sc.setAuthentication(UsernamePasswordAuthenticationToken.unauthenticated("Foobar", "pass"));
		SecurityContextHolder.setContext(sc);
		assertThat(SecurityContextHolder.getContext()).isEqualTo(sc);
		SecurityContextHolder.clearContext();
		assertThat(SecurityContextHolder.getContext()).isNotSameAs(sc);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testNeverReturnsNull() {
		assertThat(SecurityContextHolder.getContext()).isNotNull();
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testRejectsNulls() {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityContextHolder.setContext(null));
	}

	@Test
	public void setContextHolderStrategyWhenCalledThenUsed() {
		SecurityContextHolderStrategy original = SecurityContextHolder.getContextHolderStrategy();
		try {
			SecurityContextHolderStrategy delegate = mock(SecurityContextHolderStrategy.class);
			SecurityContextHolder.setContextHolderStrategy(delegate);
			SecurityContextHolder.getContext();
			verify(delegate).getContext();
		}
		finally {
			SecurityContextHolder.setContextHolderStrategy(original);
		}
	}

}
