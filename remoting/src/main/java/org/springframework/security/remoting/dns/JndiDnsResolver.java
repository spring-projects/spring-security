/*
 * Copyright 2009-2021 the original author or authors.
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

import java.util.Arrays;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

/**
 * Implementation of DnsResolver which uses JNDI for the DNS queries.
 *
 * Uses an <b>InitialContextFactory</b> to get the JNDI DirContext. The default
 * implementation will just create a new Context with the context factory
 * <b>com.sun.jndi.dns.DnsContextFactory</b>
 *
 * @author Mike Wiesner
 * @author Kathryn Newbould
 * @since 3.0
 * @see DnsResolver
 * @see InitialContextFactory
 */
public class JndiDnsResolver implements DnsResolver {

	private InitialContextFactory ctxFactory = new DefaultInitialContextFactory();

	private static final int SERVICE_RECORD_PRIORITY_INDEX = 0;

	private static final int SERVICE_RECORD_WEIGHT_INDEX = 1;

	private static final int SERVICE_RECORD_PORT_INDEX = 2;

	private static final int SERVICE_RECORD_TARGET_INDEX = 3;

	/**
	 * Allows to inject an own JNDI context factory.
	 * @param ctxFactory factory to use, when a DirContext is needed
	 * @see InitialDirContext
	 * @see DirContext
	 */
	public void setCtxFactory(InitialContextFactory ctxFactory) {
		this.ctxFactory = ctxFactory;
	}

	@Override
	public String resolveIpAddress(String hostname) {
		return resolveIpAddress(hostname, this.ctxFactory.getCtx());
	}

	@Override
	public String resolveServiceEntry(String serviceType, String domain) {
		return resolveServiceEntry(serviceType, domain, this.ctxFactory.getCtx()).getHostName();
	}

	@Override
	public String resolveServiceIpAddress(String serviceType, String domain) {
		DirContext ctx = this.ctxFactory.getCtx();
		String hostname = resolveServiceEntry(serviceType, domain, ctx).getHostName();
		return resolveIpAddress(hostname, ctx);
	}

	/**
	 * Resolves the host name for the specified service and then the IP Address and port
	 * for this host in one call.
	 * @param serviceType The service type you are searching for, e.g. ldap, kerberos, ...
	 * @param domain The domain, in which you are searching for the service
	 * @return IP address and port of the service, formatted [ip_address]:[port]
	 * @throws DnsEntryNotFoundException No record found
	 * @throws DnsLookupException Unknown DNS error
	 * @since 5.6
	 * @see #resolveServiceEntry(String, String)
	 * @see #resolveServiceIpAddress(String, String)
	 */
	public String resolveServiceIpAddressAndPort(String serviceType, String domain) {
		DirContext ctx = this.ctxFactory.getCtx();
		ConnectionInfo hostInfo = resolveServiceEntry(serviceType, domain, ctx);
		return resolveIpAddress(hostInfo.getHostName(), ctx) + ":" + hostInfo.getPort();
	}

	// This method is needed, so that we can use only one DirContext for
	// resolveServiceIpAddress().
	private String resolveIpAddress(String hostname, DirContext ctx) {
		try {
			Attribute dnsRecord = lookup(hostname, ctx, "A");
			// There should be only one A record, therefore it is save to return
			// only the first.
			return dnsRecord.get().toString();
		}
		catch (NamingException ex) {
			throw new DnsLookupException("DNS lookup failed for: " + hostname, ex);
		}

	}

	// This method is needed, so that we can use only one DirContext for
	// resolveServiceIpAddress().
	private ConnectionInfo resolveServiceEntry(String serviceType, String domain, DirContext ctx) {
		String target = null;
		String port = null;
		try {
			String query = new StringBuilder("_").append(serviceType).append("._tcp.").append(domain).toString();
			Attribute dnsRecord = lookup(query, ctx, "SRV");
			// There are maybe more records defined, we will return the one
			// with the highest priority (lowest number) and the highest weight
			// (highest number)
			int highestPriority = -1;
			int highestWeight = -1;
			for (NamingEnumeration<?> recordEnum = dnsRecord.getAll(); recordEnum.hasMoreElements();) {
				String[] record = recordEnum.next().toString().split(" ");
				if (record.length != 4) {
					throw new DnsLookupException(
							"Wrong service record for query " + query + ": [" + Arrays.toString(record) + "]");
				}
				int priority = Integer.parseInt(record[SERVICE_RECORD_PRIORITY_INDEX]);
				int weight = Integer.parseInt(record[SERVICE_RECORD_WEIGHT_INDEX]);
				// we have a new highest Priority, so forget also the highest weight
				if (priority < highestPriority || highestPriority == -1) {
					highestPriority = priority;
					highestWeight = weight;
					target = record[SERVICE_RECORD_TARGET_INDEX].trim();
					port = record[SERVICE_RECORD_PORT_INDEX].trim();
				}
				// same priority, but higher weight
				if (priority == highestPriority && weight > highestWeight) {
					highestWeight = weight;
					target = record[SERVICE_RECORD_TARGET_INDEX].trim();
					port = record[SERVICE_RECORD_PORT_INDEX].trim();
				}
			}
		}
		catch (NamingException ex) {
			throw new DnsLookupException("DNS lookup failed for service " + serviceType + " at " + domain, ex);
		}
		// remove the "." at the end
		if (target.endsWith(".")) {
			target = target.substring(0, target.length() - 1);
		}
		return new ConnectionInfo(target, port);
	}

	private Attribute lookup(String query, DirContext ictx, String recordType) {
		try {
			Attributes dnsResult = ictx.getAttributes(query, new String[] { recordType });
			return dnsResult.get(recordType);
		}
		catch (NamingException ex) {
			if (ex instanceof NameNotFoundException) {
				throw new DnsEntryNotFoundException("DNS entry not found for:" + query, ex);
			}
			throw new DnsLookupException("DNS lookup failed for: " + query, ex);
		}
	}

	private static class DefaultInitialContextFactory implements InitialContextFactory {

		@Override
		public DirContext getCtx() {
			Hashtable<String, String> env = new Hashtable<>();
			env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
			env.put(Context.PROVIDER_URL, "dns:"); // This is needed for IBM JDK/JRE
			try {
				return new InitialDirContext(env);
			}
			catch (NamingException ex) {
				throw new DnsLookupException("Cannot create InitialDirContext for DNS lookup", ex);
			}
		}

	}

	private static class ConnectionInfo {

		private final String hostName;

		private final String port;

		ConnectionInfo(String hostName, String port) {
			this.hostName = hostName;
			this.port = port;
		}

		String getHostName() {
			return this.hostName;
		}

		String getPort() {
			return this.port;
		}

	}

}
