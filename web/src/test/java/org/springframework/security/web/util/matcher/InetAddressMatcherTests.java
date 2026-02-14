/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.util.matcher;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link InetAddressMatcher}.
 *
 * @author Rob Winch
 */
class InetAddressMatcherTests {

	@Test
	void matchesWhenStringValidIpv4ThenReturnsTrue() {
		InetAddressMatcher matcher = (address) -> address.getHostAddress().equals("192.168.1.1");
		assertThat(matcher.matches("192.168.1.1")).isTrue();
	}

	@Test
	void matchesWhenStringValidIpv6ThenReturnsTrue() {
		InetAddressMatcher matcher = (address) -> address.getHostAddress().equals("fe80:0:0:0:21f:5bff:fe33:bd68");
		assertThat(matcher.matches("fe80::21f:5bff:fe33:bd68")).isTrue();
	}

	@Test
	void matchesWhenStringNullThenReturnsFalse() {
		InetAddressMatcher matcher = (address) -> true;
		assertThat(matcher.matches((String) null)).isFalse();
	}

	@Test
	void matchesWhenStringInvalidThenThrowsIllegalArgumentException() {
		InetAddressMatcher matcher = (address) -> true;
		assertThat(matcher.matches("192.168.1.1")).isTrue();
		assertThatIllegalArgumentException().isThrownBy(() -> matcher.matches("not.an.ip.address"));
	}

	@Test
	void matchesWhenStringMatchesPredicateThenReturnsTrue() {
		InetAddressMatcher matcher = (address) -> address.getHostAddress().startsWith("192.168");
		assertThat(matcher.matches("192.168.1.1")).isTrue();
		assertThat(matcher.matches("192.168.100.200")).isTrue();
	}

	@Test
	void matchesWhenStringDoesNotMatchPredicateThenReturnsFalse() {
		InetAddressMatcher matcher = (address) -> address.getHostAddress().startsWith("192.168");
		assertThat(matcher.matches("10.0.0.1")).isFalse();
	}

}
