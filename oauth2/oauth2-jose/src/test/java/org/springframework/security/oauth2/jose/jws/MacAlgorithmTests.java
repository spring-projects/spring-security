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
package org.springframework.security.oauth2.jose.jws;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link MacAlgorithm}
 *
 * @author Joe Grandja
 * @since 5.2
 */
public class MacAlgorithmTests {

	@Test
	public void fromWhenAlgorithmValidThenResolves() {
		assertThat(MacAlgorithm.from(JwsAlgorithms.HS256)).isEqualTo(MacAlgorithm.HS256);
		assertThat(MacAlgorithm.from(JwsAlgorithms.HS384)).isEqualTo(MacAlgorithm.HS384);
		assertThat(MacAlgorithm.from(JwsAlgorithms.HS512)).isEqualTo(MacAlgorithm.HS512);
	}

	@Test
	public void fromWhenAlgorithmInvalidThenDoesNotResolve() {
		assertThat(MacAlgorithm.from("invalid")).isNull();
	}

}
