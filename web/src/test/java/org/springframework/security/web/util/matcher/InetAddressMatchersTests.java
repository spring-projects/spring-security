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

import java.net.InetAddress;
import java.util.List;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link InetAddressMatchers}.
 *
 * @author Rob Winch
 */
class InetAddressMatchersTests {

	@Test
	void builderWhenInvokedThenReturnsBuilder() {
		assertThat(InetAddressMatchers.builder()).isNotNull();
	}

	@Test
	void matchExternalWhenInvokedThenReturnsBuilder() {
		InetAddressMatchers.Builder builder = InetAddressMatchers.matchExternal();
		assertThat(builder).isNotNull();
	}

	@Test
	void matchInternalWhenInvokedThenReturnsBuilder() {
		InetAddressMatchers.Builder builder = InetAddressMatchers.matchInternal();
		assertThat(builder).isNotNull();
	}

	@Nested
	class BuilderTests {

		@Test
		void includeAddressesWhenNullThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException().isThrownBy(() -> InetAddressMatchers.builder().includeAddresses(null))
				.withMessage("addresses cannot be empty");
		}

		@Test
		void includeAddressesWhenEmptyListThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException()
				.isThrownBy(() -> InetAddressMatchers.builder().includeAddresses(List.of()))
				.withMessage("addresses cannot be empty");
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "192.168.1.2" })
		void includeAddressesWhenSingleAddressThenMatchesOnlyThatAddress(String testAddress) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder().includeAddresses(List.of("192.168.1.1")).build();
			InetAddress address = InetAddress.getByName(testAddress);
			boolean expected = testAddress.equals("192.168.1.1");
			assertThat(matcher.matches(address)).isEqualTo(expected);
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "10.0.0.1", "8.8.8.8" })
		void includeAddressesWhenMultipleAddressesThenMatchesAny(String testAddress) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder()
				.includeAddresses(List.of("192.168.1.1", "10.0.0.1"))
				.build();
			InetAddress address = InetAddress.getByName(testAddress);
			boolean expected = testAddress.equals("192.168.1.1") || testAddress.equals("10.0.0.1");
			assertThat(matcher.matches(address)).isEqualTo(expected);
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "192.168.1.255", "192.168.2.1" })
		void includeAddressesWhenCidrNotationThenMatchesSubnet(String testAddress) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder()
				.includeAddresses(List.of("192.168.1.0/24"))
				.build();
			InetAddress address = InetAddress.getByName(testAddress);
			boolean expected = testAddress.startsWith("192.168.1.");
			assertThat(matcher.matches(address)).isEqualTo(expected);
		}

		@Test
		void excludeAddressesWhenNullThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException().isThrownBy(() -> InetAddressMatchers.builder().excludeAddresses(null))
				.withMessage("addresses cannot be empty");
		}

		@Test
		void excludeAddressesWhenEmptyListThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException()
				.isThrownBy(() -> InetAddressMatchers.builder().excludeAddresses(List.of()))
				.withMessage("addresses cannot be empty");
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "192.168.1.2" })
		void excludeAddressesWhenSingleAddressThenBlocksOnlyThatAddress(String testAddress) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder().excludeAddresses(List.of("192.168.1.1")).build();
			InetAddress address = InetAddress.getByName(testAddress);
			boolean expected = !testAddress.equals("192.168.1.1");
			assertThat(matcher.matches(address)).isEqualTo(expected);
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "10.0.0.1", "8.8.8.8" })
		void excludeAddressesWhenMultipleAddressesThenBlocksAll(String testAddress) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder()
				.excludeAddresses(List.of("192.168.1.1", "10.0.0.1"))
				.build();
			InetAddress address = InetAddress.getByName(testAddress);
			boolean expected = !testAddress.equals("192.168.1.1") && !testAddress.equals("10.0.0.1");
			assertThat(matcher.matches(address)).isEqualTo(expected);
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "192.168.1.255", "192.168.2.1" })
		void excludeAddressesWhenCidrNotationThenBlocksSubnet(String testAddress) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder()
				.excludeAddresses(List.of("192.168.1.0/24"))
				.build();
			InetAddress address = InetAddress.getByName(testAddress);
			boolean expected = !testAddress.startsWith("192.168.1.");
			assertThat(matcher.matches(address)).isEqualTo(expected);
		}

		@ParameterizedTest
		@ValueSource(strings = { "10.0.0.1", "192.168.1.1" })
		void matchAllWhenVarargsThenAddsMatchersToChain(String testAddress) throws Exception {
			InetAddressMatcher customMatcher = (address) -> address.getHostAddress().startsWith("10.");
			InetAddressMatcher matcher = InetAddressMatchers.builder().matchAll(customMatcher).build();
			InetAddress address = InetAddress.getByName(testAddress);
			boolean expected = testAddress.startsWith("10.");
			assertThat(matcher.matches(address)).isEqualTo(expected);
		}

		@Test
		void matchAllWhenNullVarargsThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException()
				.isThrownBy(() -> InetAddressMatchers.builder().matchAll((InetAddressMatcher[]) null))
				.withMessage("matchers cannot be empty");
		}

		@Test
		void matchAllWhenEmptyVarargsThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException()
				.isThrownBy(() -> InetAddressMatchers.builder().matchAll(new InetAddressMatcher[0]))
				.withMessage("matchers cannot be empty");
		}

		@ParameterizedTest
		@ValueSource(strings = { "10.0.0.1", "10.0.0.2", "192.168.1.1" })
		void matchAllWhenMultipleMatchersThenAppliesAndLogic(String testAddress) throws Exception {
			InetAddressMatcher startsWithTen = (address) -> address.getHostAddress().startsWith("10.");
			InetAddressMatcher endsWithOne = (address) -> address.getHostAddress().endsWith(".1");
			InetAddressMatcher matcher = InetAddressMatchers.builder().matchAll(startsWithTen, endsWithOne).build();
			InetAddress address = InetAddress.getByName(testAddress);
			boolean expected = testAddress.startsWith("10.") && testAddress.endsWith(".1");
			assertThat(matcher.matches(address)).isEqualTo(expected);
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "8.8.8.8" })
		void reportOnlyWhenSetThenAllowsAllAddresses(String testAddress) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder()
				.excludeAddresses(List.of("192.168.1.1"))
				.reportOnly()
				.build();
			InetAddress address = InetAddress.getByName(testAddress);
			assertThat(matcher.matches(address)).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "192.168.1.100", "192.168.2.1" })
		void buildWhenMultipleMatchersThenAppliesAndLogic(String testAddress) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder()
				.includeAddresses(List.of("192.168.1.0/24"))
				.excludeAddresses(List.of("192.168.1.100"))
				.build();
			InetAddress address = InetAddress.getByName(testAddress);
			boolean expected = testAddress.startsWith("192.168.1.") && !testAddress.equals("192.168.1.100");
			assertThat(matcher.matches(address)).isEqualTo(expected);
		}

	}

	@Nested
	class IncludeListInetAddressMatcherTests {

		@Test
		void constructorWhenNullListThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException()
				.isThrownBy(() -> new InetAddressMatchers.IncludeListInetAddressMatcher(null))
				.withMessage("includeList cannot be null or empty");
		}

		@Test
		void constructorWhenEmptyListThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException()
				.isThrownBy(() -> new InetAddressMatchers.IncludeListInetAddressMatcher(List.of()))
				.withMessage("includeList cannot be null or empty");
		}

		@Test
		void matchesWhenAddressInListThenReturnsTrue() throws Exception {
			String addressString = "192.168.1.1";
			InetAddressMatcher matcher = InetAddressMatchers.builder().includeAddresses(List.of(addressString)).build();
			assertThat(matcher.matches(InetAddress.getByName(addressString))).isTrue();
		}

		@Test
		void matchesWhenAddressNotInListThenReturnsFalse() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder().includeAddresses(List.of("192.168.1.1")).build();
			assertThat(matcher.matches(InetAddress.getByName("192.168.1.2"))).isFalse();
		}

	}

	@Nested
	class ExcludeListInetAddressMatcherTests {

		@Test
		void constructorWhenNullListThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException()
				.isThrownBy(() -> new InetAddressMatchers.ExcludeListInetAddressMatcher(null))
				.withMessage("excludeList cannot be null or empty");
		}

		@Test
		void constructorWhenEmptyListThenThrowsIllegalArgumentException() {
			assertThatIllegalArgumentException()
				.isThrownBy(() -> new InetAddressMatchers.ExcludeListInetAddressMatcher(List.of()))
				.withMessage("excludeList cannot be null or empty");
		}

		@Test
		void matchesWhenAddressInListThenReturnsFalse() throws Exception {
			String addressString = "192.168.1.1";
			InetAddressMatcher matcher = InetAddressMatchers.builder().excludeAddresses(List.of(addressString)).build();
			assertThat(matcher.matches(InetAddress.getByName(addressString))).isFalse();
		}

		@Test
		void matchesWhenAddressNotInListThenReturnsTrue() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder().excludeAddresses(List.of("192.168.1.1")).build();
			assertThat(matcher.matches(InetAddress.getByName("192.168.1.2"))).isTrue();
		}

	}

	@Nested
	class InternalInetAddressMatcherTests {

		@Test
		void matchesWhenInetAddressNullThenReturnsFalse() {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches((InetAddress) null)).isFalse();
		}

		@ParameterizedTest
		@ValueSource(strings = { "127.0.0.1", "127.0.0.255" })
		void matchesWhenIpv4LoopbackThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@Test
		void matchesWhenIpv6LoopbackThenReturnsTrue() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName("::1"))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "10.0.0.1", "10.255.255.255" })
		void matchesWhenIpv4PrivateClass10ThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.0.1", "192.168.255.255" })
		void matchesWhenIpv4PrivateClass192ThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "169.254.0.0", "169.254.169.254", "169.254.255.255" })
		void matchesWhenIpv4LinkLocalThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "172.16.0.1", "172.16.255.255", "172.17.1.1", "172.31.255.255" })
		void matchesWhenIpv4PrivateClass172ThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "::ffff:192.168.1.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1" })
		void matchesWhenIpv4MappedIpv6InternalThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "fc00::1", "fd00::1" })
		void matchesWhenIpv6UniqueLocalThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(
				strings = { "64:ff9b::10.0.0.1", "64:ff9b::127.0.0.1", "64:ff9b::192.168.1.1", "64:ff9b::172.16.0.1" })
		void matchesWhenIpv6TranslationWithInternalIpv4ThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "64:ff9b::192.0.2.1", "64:ff9b::192.167.1.1" })
		void matchesWhenIpv6TranslationWithIpv4StartsWith192ButNot168ThenReturnsFalse(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isFalse();
		}

		@ParameterizedTest
		@ValueSource(strings = { "64:ff9b::172.16.0.1", "64:ff9b::172.16.255.255" })
		void matchesWhenIpv6TranslationWithIpv4StartsWith172And16ThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "64:ff9b::8.8.8.8", "64:ff9b::1.1.1.1" })
		void matchesWhenIpv6TranslationWithExternalIpv4ThenReturnsFalse(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isFalse();
		}

		@Test
		void matchesWhenIpv6NonTranslationPrefixByte0ThenReturnsFalse() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName("65:ff9b::10.0.0.1"))).isFalse();
		}

		@Test
		void matchesWhenIpv6NonTranslationPrefixByte1ThenReturnsFalse() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName("64:fe9b::10.0.0.1"))).isFalse();
		}

		@Test
		void matchesWhenIpv6NonTranslationPrefixByte2ThenReturnsFalse() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName("64:ff9a::10.0.0.1"))).isFalse();
		}

		@Test
		void matchesWhenIpv6NonTranslationPrefixByte3ThenReturnsFalse() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName("64:ff9c::10.0.0.1"))).isFalse();
		}

		@ParameterizedTest
		@ValueSource(strings = { "8.8.8.8", "1.1.1.1" })
		void matchesWhenIpv4PublicThenReturnsFalse(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isFalse();
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.0.2.1", "192.167.1.1", "192.169.1.1" })
		void matchesWhenIpv4StartsWith192ButNot168ThenReturnsFalse(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isFalse();
		}

		@ParameterizedTest
		@ValueSource(strings = { "172.15.1.1", "172.32.1.1" })
		void matchesWhenIpv4StartsWith172ButNotPrivate16To31ThenReturnsFalse(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isFalse();
		}

		@Test
		void matchesWhenIpv6PublicThenReturnsFalse() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchInternal().build();
			assertThat(matcher.matches(InetAddress.getByName("2001:4860:4860::8888"))).isFalse();
		}

	}

	@Nested
	class ExternalInetAddressMatcherTests {

		@ParameterizedTest
		@ValueSource(strings = { "8.8.8.8", "1.1.1.1" })
		void matchesWhenIpv4PublicThenReturnsTrue(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchExternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isTrue();
		}

		@Test
		void matchesWhenIpv6PublicThenReturnsTrue() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchExternal().build();
			assertThat(matcher.matches(InetAddress.getByName("2001:4860:4860::8888"))).isTrue();
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "10.0.0.1", "172.16.0.1" })
		void matchesWhenIpv4PrivateThenReturnsFalse(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchExternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isFalse();
		}

		@Test
		void matchesWhenIpv4LoopbackThenReturnsFalse() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchExternal().build();
			assertThat(matcher.matches(InetAddress.getByName("127.0.0.1"))).isFalse();
		}

		@ParameterizedTest
		@ValueSource(strings = { "169.254.0.0", "169.254.169.254", "169.254.255.255" })
		void matchesWhenIpv4LinkLocalThenReturnsFalse(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchExternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isFalse();
		}

		@Test
		void matchesWhenIpv6LoopbackThenReturnsFalse() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchExternal().build();
			assertThat(matcher.matches(InetAddress.getByName("::1"))).isFalse();
		}

		@ParameterizedTest
		@ValueSource(strings = { "fc00::1", "fd00::1" })
		void matchesWhenIpv6UniqueLocalThenReturnsFalse(String address) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.matchExternal().build();
			assertThat(matcher.matches(InetAddress.getByName(address))).isFalse();
		}

	}

	@Nested
	class CompositeInetAddressMatcherTests {

		@Test
		void matchesWhenAllMatchersTrueThenReturnsTrue() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder()
				.includeAddresses(List.of("192.168.1.0/24"))
				.matchAll((address) -> address.getHostAddress().endsWith(".1"))
				.build();
			assertThat(matcher.matches(InetAddress.getByName("192.168.1.1"))).isTrue();
		}

		@Test
		void matchesWhenOneMatcherFalseThenReturnsFalse() throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder()
				.includeAddresses(List.of("192.168.1.0/24"))
				.matchAll((address) -> address.getHostAddress().endsWith(".1"))
				.build();
			assertThat(matcher.matches(InetAddress.getByName("192.168.1.2"))).isFalse();
		}

		@ParameterizedTest
		@ValueSource(strings = { "192.168.1.1", "8.8.8.8" })
		void matchesWhenReportOnlyThenAlwaysReturnsTrue(String testAddress) throws Exception {
			InetAddressMatcher matcher = InetAddressMatchers.builder()
				.excludeAddresses(List.of("192.168.1.1"))
				.reportOnly()
				.build();
			assertThat(matcher.matches(InetAddress.getByName(testAddress))).isTrue();
		}

	}

}
