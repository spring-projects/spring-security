/*
 * Copyright 2009-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.remoting.dns;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Comparator.comparing;

/**
 * Implementation of DnsResolver which uses JNDI for the DNS queries.
 *
 * Uses an <b>InitialContextFactory</b> to get the JNDI DirContext. The default
 * implementation will just create a new Context with the context factory
 * <b>com.sun.jndi.dns.DnsContextFactory</b>
 *
 * @author Mike Wiesner
 * @since 3.0
 * @see DnsResolver
 * @see InitialContextFactory
 */
public class JndiDnsResolver implements DnsResolver {

	private InitialContextFactory ctxFactory = new DefaultInitialContextFactory();

	/**
	 * Allows to inject an own JNDI context factory.
	 *
	 * @param ctxFactory factory to use, when a DirContext is needed
	 * @see InitialDirContext
	 * @see DirContext
	 */
	public void setCtxFactory(InitialContextFactory ctxFactory) {
		this.ctxFactory = ctxFactory;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.remoting.dns.DnsResolver#resolveIpAddress(java.lang
	 * .String)
	 */
	public String resolveIpAddress(String hostname) {
		return resolveIpAddress(hostname, this.ctxFactory.getCtx());
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.remoting.dns.DnsResolver#resolveServiceEntry(java.
	 * lang.String, java.lang.String)
	 */
	public String resolveServiceEntry(String serviceType, String domain) {
		return resolveServiceEntry(serviceType, domain, this.ctxFactory.getCtx());
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.remoting.dns.DnsResolver#resolveAllServiceEntries(java.
	 * lang.String, java.lang.String)
	 */
	public List<String> resolveAllServiceEntries(String serviceType, String domain) {
		List<DnsRecord> dnsRecords = lookupDnsRecords(serviceType, domain, this.ctxFactory.getCtx());
		return dnsRecords
			.stream()
			.map(DnsRecord::getHostName)
			.collect(Collectors.toList());
	}

	// There may be multiple records defined, we will return a list ordered on priority and weight
	private List<DnsRecord> lookupDnsRecords(String serviceType, String domain,
											 DirContext ctx) {
		List<DnsRecord> records = new ArrayList<>();
		try {
			String query = new StringBuilder("_").append(serviceType).append("._tcp.")
				.append(domain).toString();
			Attribute dnsRecord = lookup(query, ctx, "SRV");

			for (NamingEnumeration<?> recordEnum = dnsRecord.getAll(); recordEnum
				.hasMoreElements();) {
				String[] record = recordEnum.next().toString().split(" ");
				if (record.length != 4) {
					throw new DnsLookupException("Wrong service record for query " + query
						+ ": [" + Arrays.toString(record) + "]");
				}
				int priority = Integer.parseInt(record[0]);
				int weight = Integer.parseInt(record[1]);
				String hostName = removeTrailingDot(record[3].trim());
				records.add(new DnsRecord(hostName, priority, weight));
			}
		} catch (NamingException e) {
			throw new DnsLookupException(
				"DNS lookup failed for service " + serviceType + " at " + domain, e);
		}

		records.sort(
			comparing(DnsRecord::getPriority)
			.thenComparing((comparing(DnsRecord::getWeight)).reversed()));

		return records;
	}

	private String removeTrailingDot(String hostName) {
		if (hostName.endsWith(".")) {
			hostName = hostName.substring(0, hostName.length() - 1);
		}
		return hostName;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.remoting.dns.DnsResolver#resolveServiceIpAddress(java
	 * .lang.String, java.lang.String)
	 */
	public String resolveServiceIpAddress(String serviceType, String domain) {
		DirContext ctx = this.ctxFactory.getCtx();
		String hostname = resolveServiceEntry(serviceType, domain, ctx);
		return resolveIpAddress(hostname, ctx);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.remoting.dns.DnsResolver#resolveAllServiceIpAddresses(java
	 * .lang.String, java.lang.String)
	 */
	public List<String> resolveAllServiceIpAddresses(String serviceType, String domain) {
		List<String> hostNames = resolveAllServiceEntries(serviceType, domain);
		return hostNames
			.stream()
			.map(this::resolveIpAddress)
			.collect(Collectors.toList());
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
		catch (NamingException e) {
			throw new DnsLookupException("DNS lookup failed for: " + hostname, e);
		}

	}

	// This method is needed, so that we can use only one DirContext for
	// resolveServiceIpAddress().
	private String resolveServiceEntry(String serviceType, String domain,
									   DirContext ctx) {

		DnsRecord dnsRecord = lookupDnsRecords(serviceType, domain, ctx).get(0);
		return dnsRecord != null ? dnsRecord.getHostName() : null;
	}

	private Attribute lookup(String query, DirContext ictx, String recordType) {
		try {
			Attributes dnsResult = ictx.getAttributes(query, new String[] { recordType });

			return dnsResult.get(recordType);
		}
		catch (NamingException e) {
			if (e instanceof NameNotFoundException) {
				throw new DnsEntryNotFoundException("DNS entry not found for:" + query,
						e);
			}
			throw new DnsLookupException("DNS lookup failed for: " + query, e);
		}
	}

	private static class DefaultInitialContextFactory implements InitialContextFactory {

		public DirContext getCtx() {
			Hashtable<String, String> env = new Hashtable<String, String>();
			env.put(Context.INITIAL_CONTEXT_FACTORY,
					"com.sun.jndi.dns.DnsContextFactory");
			env.put(Context.PROVIDER_URL, "dns:"); // This is needed for IBM JDK/JRE
			InitialDirContext ictx;
			try {
				ictx = new InitialDirContext(env);
			}
			catch (NamingException e) {
				throw new DnsLookupException(
						"Cannot create InitialDirContext for DNS lookup", e);
			}
			return ictx;
		}
	}

	private class DnsRecord {
		private String hostName;
		private int priority;
		private int weight;

		DnsRecord(String hostName, int priority, int weight) {
			this.hostName = hostName;
			this.priority = priority;
			this.weight = weight;
		}

		String getHostName() {
			return hostName;
		}

		int getPriority() {
			return priority;
		}

		int getWeight() {
			return weight;
		}
	}
}
