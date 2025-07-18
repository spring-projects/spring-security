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

package client;

import client.dns.SecurityDnsHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.netty.transport.ClientTransportConfig;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class NettyHttpClientAddressSelectorTests {

    private ClientTransportConfig<?> mockConfig;

    @BeforeEach
    void setUp() {
        mockConfig = mock(ClientTransportConfig.class);
    }

    private InetSocketAddress createInetSocketAddress(String hostname, int port) {
        try {
            return new InetSocketAddress(InetAddress.getByName(hostname), port);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void selectWhenEmptyListShouldReturnEmptyList() {
        SecurityDnsHandler handler = SecurityDnsHandler.builder().build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);
        List<SocketAddress> result = selector.select(mockConfig, Collections::emptyList);
        assertTrue(result.isEmpty());
    }

    @Test
    void selectWhenNullListShouldReturnNull() {
        SecurityDnsHandler handler = SecurityDnsHandler.builder().build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);
        List<SocketAddress> result = selector.select(mockConfig, () -> null);
        assertNull(result);
    }

    @Test
    void selectWithNoFilterShouldReturnOriginalList() {
        SecurityDnsHandler handler = SecurityDnsHandler.builder().build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);
        List<SocketAddress> addresses = List.of(
                createInetSocketAddress("1.1.1.1", 80),
                createInetSocketAddress("8.8.8.8", 80)
        );
        List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
        assertEquals(addresses, result);
    }

    @Test
    void selectWithAllowListShouldFilter() {
        SecurityDnsHandler handler = SecurityDnsHandler.builder().allowList("1.1.1.1").build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);
        List<SocketAddress> addresses = List.of(
                createInetSocketAddress("1.1.1.1", 80),
                createInetSocketAddress("8.8.8.8", 80),
                createInetSocketAddress("1.0.0.1", 80)
        );
        List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
        assertEquals(List.of(createInetSocketAddress("1.1.1.1", 80)), result);
    }

    @Test
    void selectWithDenyListShouldFilter() {
        SecurityDnsHandler handler = SecurityDnsHandler.builder().denyList("8.8.8.8").build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);
        List<SocketAddress> addresses = List.of(
                createInetSocketAddress("1.1.1.1", 80),
                createInetSocketAddress("8.8.8.8", 80),
                createInetSocketAddress("1.0.0.1", 80)
        );
        List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
        assertEquals(List.of(
                createInetSocketAddress("1.1.1.1", 80),
                createInetSocketAddress("1.0.0.1", 80)
        ), result);
    }

    @Test
    void selectWithBlockExternalShouldFilter() throws UnknownHostException {
        // 10.0.0.1 is internal, 8.8.8.8 is external
        SecurityDnsHandler handler = SecurityDnsHandler.builder().blockAllExternal(true).build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);
        List<SocketAddress> addresses = List.of(
                createInetSocketAddress("10.0.0.1", 80),
                createInetSocketAddress("8.8.8.8", 80)
        );
        List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
        assertEquals(List.of(createInetSocketAddress("10.0.0.1", 80)), result);
    }

    @Test
    void selectWithBlockInternalShouldFilter() throws UnknownHostException {
        // 10.0.0.1 is internal, 8.8.8.8 is external
        SecurityDnsHandler handler = SecurityDnsHandler.builder().blockAllInternal(true).build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);
        List<SocketAddress> addresses = List.of(
                createInetSocketAddress("10.0.0.1", 80),
                createInetSocketAddress("8.8.8.8", 80)
        );
        List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
        assertEquals(List.of(createInetSocketAddress("8.8.8.8", 80)), result);
    }

    @Test
    void selectWithReportOnlyModeShouldNotFilterButLog() {
        // For logging, we can't directly assert logs here without more complex setup.
        // We'll trust SecurityDnsHandler's tests for logging and just check that reportOnly doesn't filter.
        SecurityDnsHandler handler = SecurityDnsHandler.builder().denyList("8.8.8.8").reportOnly(true).build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);
        List<SocketAddress> addresses = List.of(
                createInetSocketAddress("1.1.1.1", 80),
                createInetSocketAddress("8.8.8.8", 80)
        );
        List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
        assertEquals(addresses, result);
    }

    @Test
    void selectWithDifferentPortsShouldUseFirstPort() {
        // This test highlights the behavior of using the port from the first address.
        SecurityDnsHandler handler = SecurityDnsHandler.builder().allowList("1.1.1.1").build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);
        List<SocketAddress> addresses = List.of(
                createInetSocketAddress("1.1.1.1", 80),
                createInetSocketAddress("1.1.1.1", 443), // Same IP, different port
                createInetSocketAddress("8.8.8.8", 80)
        );
        // SecurityDnsHandler.handleInetSocketAddresses uses the port passed to it,
        // which our selector derives from the first element.
        List<SocketAddress> result = selector.select(mockConfig, () -> addresses);
        assertEquals(List.of(
                createInetSocketAddress("1.1.1.1", 80),
                createInetSocketAddress("1.1.1.1", 443)
        ), result);
    }

    @Test
    void selectWithNonInetSocketAddressShouldReturnOriginalList() {
        SecurityDnsHandler handler = SecurityDnsHandler.builder().build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);

        // Create a mock SocketAddress that is not an InetSocketAddress
        SocketAddress nonInetAddress = mock(SocketAddress.class);

        List<SocketAddress> addresses = List.of(nonInetAddress);

        List<SocketAddress> result = selector.select(mockConfig, () -> addresses);

        // Expect the original list to be returned as per the implementation logic
        assertEquals(addresses, result);
    }

    @Test
    void selectWithMixedAddressTypesShouldFilterInetSocketAddressesOnly() {
        SecurityDnsHandler handler = SecurityDnsHandler.builder().denyList("8.8.8.8").build();
        NettyHttpClientAddressSelector selector = new NettyHttpClientAddressSelector(handler);

        SocketAddress nonInetAddress = mock(SocketAddress.class);
        InetSocketAddress allowedAddress = createInetSocketAddress("1.1.1.1", 80);
        InetSocketAddress deniedAddress = createInetSocketAddress("8.8.8.8", 80);

        List<SocketAddress> addresses = List.of(
                allowedAddress,
                deniedAddress,
                nonInetAddress
        );

        List<SocketAddress> result = selector.select(mockConfig, () -> addresses);

        // The current implementation keeps non-InetSocketAddress types in the result.
        assertEquals(List.of(allowedAddress, nonInetAddress), result);
    }
}
