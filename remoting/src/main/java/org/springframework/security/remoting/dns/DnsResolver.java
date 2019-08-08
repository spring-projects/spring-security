/*
 * Copyright 2009-2016 the original author or authors.
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

package org.springframework.security.remoting.dns;

/**
 * Helper class for DNS operations.
 *
 * @author Mike Wiesner
 * @since 3.0
 */
public interface DnsResolver {

	/**
	 * Resolves the IP Address (A record) to the specified host name. Throws
	 * DnsEntryNotFoundException if there is no record.
	 *
	 * @param hostname The hostname for which you need the IP Address
	 * @return IP Address as a String
	 * @throws DnsEntryNotFoundException No record found
	 * @throws DnsLookupException Unknown DNS error
	 */
	String resolveIpAddress(String hostname) throws DnsEntryNotFoundException,
			DnsLookupException;

	/**
	 * <p>
	 * Resolves the host name for the specified service in the specified domain
	 *
	 * <p>
	 * For example, if you need the host name for an LDAP server running in the domain
	 * springsource.com, you would call <b>resolveServiceEntry("ldap",
	 * "springsource.com")</b>.
	 *
	 * <p>
	 * The DNS server needs to provide the service records for this, in the example above,
	 * it would look like this:
	 *
	 * <pre>
	 * _ldap._tcp.springsource.com IN SRV 10 0 88 ldap.springsource.com.
	 * </pre>
	 *
	 * The method will return the record with highest priority (which means the lowest
	 * number in the DNS record) and if there are more than one records with the same
	 * priority, it will return the one with the highest weight. You will find more
	 * informatione about DNS service records at <a
	 * href="https://en.wikipedia.org/wiki/SRV_record">Wikipedia</a>.
	 *
	 * @param serviceType The service type you are searching for, e.g. ldap, kerberos, ...
	 * @param domain The domain, in which you are searching for the service
	 * @return The hostname of the service
	 * @throws DnsEntryNotFoundException No record found
	 * @throws DnsLookupException Unknown DNS error
	 */
	String resolveServiceEntry(String serviceType, String domain)
			throws DnsEntryNotFoundException, DnsLookupException;

	/**
	 * Resolves the host name for the specified service and then the IP Address for this
	 * host in one call.
	 *
	 * @param serviceType The service type you are searching for, e.g. ldap, kerberos, ...
	 * @param domain The domain, in which you are searching for the service
	 * @return IP Address of the service
	 * @throws DnsEntryNotFoundException No record found
	 * @throws DnsLookupException Unknown DNS error
	 * @see #resolveServiceEntry(String, String)
	 * @see #resolveIpAddress(String)
	 */
	String resolveServiceIpAddress(String serviceType, String domain)
			throws DnsEntryNotFoundException, DnsLookupException;

}
