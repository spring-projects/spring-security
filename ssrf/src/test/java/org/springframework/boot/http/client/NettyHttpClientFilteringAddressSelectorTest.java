/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.boot.http.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.web.util.matcher.InetAddressMatcher;
import reactor.netty.transport.ClientTransportConfig;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NettyHttpClientFilteringAddressSelectorTest {

	@Mock
	private ClientTransportConfig<?> mockConfig;

	@Mock
	private InetAddressMatcher inetAddressFilter;

	private NettyHttpClientFilteringAddressSelector selector;

	@BeforeEach
	void setUp() {
		selector = new NettyHttpClientFilteringAddressSelector(inetAddressFilter);
	}

	private InetSocketAddress createInetSocketAddress(String hostname, int port) {
		try {
			return new InetSocketAddress(InetAddress.getByName(hostname), port);
		}
		catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	void selectWhenEmptyListShouldReturnEmptyList() {
		List<SocketAddress> result = selector.select(mockConfig, Collections::emptyList);
		assertTrue(result.isEmpty());
		verify(this.inetAddressFilter, never()).matches(any(InetAddress.class));
	}

	@Test
	void selectWhenNullListShouldReturnNull() {
		List<SocketAddress> result = selector.select(mockConfig, () -> null);
		assertNull(result);
		verify(this.inetAddressFilter, never()).matches(any(InetAddress.class));
	}

	@Test
	void selectWhenAllAddressesAreAllowed() {
		InetSocketAddress address1 = createInetSocketAddress("1.1.1.1", 80);
		InetSocketAddress address2 = createInetSocketAddress("8.8.8.8", 80);
		List<SocketAddress> addresses = List.of(address1, address2);

		when(this.inetAddressFilter.matches(address1.getAddress())).thenReturn(true);
		when(this.inetAddressFilter.matches(address2.getAddress())).thenReturn(true);

		List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
		List<String> resultStrings = result.stream()
				.map(sa -> ((InetSocketAddress) sa).getAddress().getHostAddress() + ":" + ((InetSocketAddress) sa).getPort())
				.collect(java.util.stream.Collectors.toList());
		List<String> expectedStrings = addresses.stream()
				.map(sa -> ((InetSocketAddress) sa).getAddress().getHostAddress() + ":" + ((InetSocketAddress) sa).getPort())
				.collect(java.util.stream.Collectors.toList());
		assertEquals(expectedStrings, resultStrings);
		verify(this.inetAddressFilter, times(1)).matches(address1.getAddress());
		verify(this.inetAddressFilter, times(1)).matches(address2.getAddress());
	}

	@Test
	void selectWhenSomeAddressesAreDenied() {
		InetSocketAddress allowedAddress = createInetSocketAddress("1.1.1.1", 80);
		InetSocketAddress deniedAddress = createInetSocketAddress("8.8.8.8", 80);
		InetSocketAddress anotherAllowedAddress = createInetSocketAddress("1.0.0.1", 80);
		List<SocketAddress> addresses = List.of(allowedAddress, deniedAddress, anotherAllowedAddress);

		when(this.inetAddressFilter.matches(allowedAddress.getAddress())).thenReturn(true);
		when(this.inetAddressFilter.matches(deniedAddress.getAddress())).thenReturn(false);
		when(this.inetAddressFilter.matches(anotherAllowedAddress.getAddress())).thenReturn(true);

		List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
		List<String> resultStrings = result.stream()
				.map(sa -> ((InetSocketAddress) sa).getAddress().getHostAddress() + ":" + ((InetSocketAddress) sa).getPort())
				.collect(java.util.stream.Collectors.toList());
		List<String> expectedStrings = List.of(allowedAddress, anotherAllowedAddress).stream()
				.map(sa -> ((InetSocketAddress) sa).getAddress().getHostAddress() + ":" + ((InetSocketAddress) sa).getPort())
				.collect(java.util.stream.Collectors.toList());
		assertEquals(expectedStrings, resultStrings);
		verify(this.inetAddressFilter, times(1)).matches(allowedAddress.getAddress());
		verify(this.inetAddressFilter, times(1)).matches(deniedAddress.getAddress());
		verify(this.inetAddressFilter, times(1)).matches(anotherAllowedAddress.getAddress());
	}

	@Test
	void selectWhenAllAddressesAreDenied() {
		InetSocketAddress deniedAddress1 = createInetSocketAddress("1.1.1.1", 80);
		InetSocketAddress deniedAddress2 = createInetSocketAddress("8.8.8.8", 80);
		List<SocketAddress> addresses = List.of(deniedAddress1, deniedAddress2);

		when(this.inetAddressFilter.matches(deniedAddress1.getAddress())).thenReturn(false);
		when(this.inetAddressFilter.matches(deniedAddress2.getAddress())).thenReturn(false);

		List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
		List<String> resultStrings = result.stream()
				.map(sa -> ((InetSocketAddress) sa).getAddress().getHostAddress() + ":" + ((InetSocketAddress) sa).getPort())
				.collect(java.util.stream.Collectors.toList());
		List<String> expectedStrings = Collections.emptyList(); // All denied, so expected is empty
		assertEquals(expectedStrings, resultStrings);
		verify(this.inetAddressFilter, times(1)).matches(deniedAddress1.getAddress());
		verify(this.inetAddressFilter, times(1)).matches(deniedAddress2.getAddress());
	}


	@Test
	void selectWithNonInetSocketAddressShouldReturnOriginalIfFilterPasses() {
		SocketAddress nonInetAddress = mock(SocketAddress.class);
		InetSocketAddress allowedAddress = createInetSocketAddress("1.1.1.1", 80);
		List<SocketAddress> addresses = List.of(nonInetAddress, allowedAddress);

		when(this.inetAddressFilter.matches(allowedAddress.getAddress())).thenReturn(true);

		List<SocketAddress> result = selector.select(mockConfig, () -> addresses);

		assertEquals(2, result.size());
		assertTrue(result.contains(nonInetAddress));
		assertTrue(result.contains(allowedAddress));
		verify(this.inetAddressFilter, times(1)).matches(allowedAddress.getAddress());
	}

	@Test
	void selectWithMixedAddressTypesAndFiltering() {
		SocketAddress nonInetAddress = mock(SocketAddress.class);
		InetSocketAddress allowedAddress = createInetSocketAddress("1.1.1.1", 80);
		InetSocketAddress deniedAddress = createInetSocketAddress("8.8.8.8", 80);

		List<SocketAddress> addresses = List.of(allowedAddress, deniedAddress, nonInetAddress);

		when(this.inetAddressFilter.matches(allowedAddress.getAddress())).thenReturn(true);
		when(this.inetAddressFilter.matches(deniedAddress.getAddress())).thenReturn(false);

		List<SocketAddress> result = selector.select(mockConfig, () -> addresses);

		assertEquals(2, result.size());
		assertTrue(result.contains(nonInetAddress));
		assertTrue(result.contains(allowedAddress));
		verify(this.inetAddressFilter, times(1)).matches(allowedAddress.getAddress());
		verify(this.inetAddressFilter, times(1)).matches(deniedAddress.getAddress());
	}

}
