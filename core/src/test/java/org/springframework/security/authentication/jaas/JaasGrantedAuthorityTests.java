/*
 * Copyright 2002-2019 the original author or authors.
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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Clement Ng
 *
 */
public class JaasGrantedAuthorityTests {

	@Test
	public void authorityWithNullRoleFailsAssertion() {
		assertThatIllegalArgumentException().isThrownBy(() -> new JaasGrantedAuthority(null, null))
				.withMessageContaining("role cannot be null");
	}

	@Test
	public void authorityWithNullPrincipleFailsAssertion() {
		assertThatIllegalArgumentException().isThrownBy(() -> new JaasGrantedAuthority("role", null))
				.withMessageContaining("principal cannot be null");
	}

}
