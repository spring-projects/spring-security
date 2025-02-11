/*
 * Copyright 2002-2024 the original author or authors.
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
package com.google.springframework.security.web.client;

import java.net.InetAddress;

/**
 * The interface which is used to implement all filtering logic in the DNS resolvers used by {@link SecureRestTemplate}.
 */
public interface SsrfProtectionFilter {

	/**
	 * Because a hostname can be resolved to multiple addresses ( e.g. round-robin DNS ) all implementations
	 * must check that all the address conform to their internal filtering logic.
	 *
	 * @param addresses list addresses to checked against a filtering criteria.
	 * @return the list of InetAddress that pass through the filter
     *
	 * @throws HostBlockedException when there are no addresses that pass the filtering criteria this exception should be thrown.
	 */

	InetAddress[] filterAddresses(final InetAddress[] addresses) throws HostBlockedException;

}
