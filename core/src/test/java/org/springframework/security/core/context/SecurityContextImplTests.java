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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Tests {@link SecurityContextImpl}.
 *
 * @author Ben Alex
 */
public class SecurityContextImplTests {
	// ~ Constructors
	// ===================================================================================================

	public SecurityContextImplTests() {
		super();
	}

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testEmptyObjectsAreEquals() {
		SecurityContextImpl obj1 = new SecurityContextImpl();
		SecurityContextImpl obj2 = new SecurityContextImpl();
		assertThat(obj1.equals(obj2)).isTrue();
	}

	@Test
	public void testSecurityContextCorrectOperation() {
		SecurityContext context = new SecurityContextImpl();
		Authentication auth = new UsernamePasswordAuthenticationToken("rod", "koala");
		context.setAuthentication(auth);
		assertThat(context.getAuthentication()).isEqualTo(auth);
		assertThat(context.toString().lastIndexOf("rod") != -1).isTrue();
	}
}
