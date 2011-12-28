/*
 * Copyright 2009 the original author or authors.
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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Mike Wiesner
 * @since 3.0
 */
public class JndiDnsResolverTests {

    private JndiDnsResolver dnsResolver;
    private InitialContextFactory contextFactory;
    private DirContext context;

    @Before
    public void setup() {
        contextFactory = mock(InitialContextFactory.class);
        context = mock(DirContext.class);
        dnsResolver = new JndiDnsResolver();
        dnsResolver.setCtxFactory(contextFactory);
        when(contextFactory.getCtx()).thenReturn(context);
    }

    @Test
    public void testResolveIpAddress() throws Exception {
        Attributes records = new BasicAttributes("A","63.246.7.80");

        when(context.getAttributes("www.springsource.com", new String[] {"A"})).thenReturn(records);

        String ipAddress = dnsResolver.resolveIpAddress("www.springsource.com");
        assertEquals("63.246.7.80", ipAddress);
    }

    @Test(expected=DnsEntryNotFoundException.class)
    public void testResolveIpAddressNotExisting() throws Exception {
        when(context.getAttributes(any(String.class), any(String[].class))).thenThrow(new NameNotFoundException("not found"));

        dnsResolver.resolveIpAddress("notexisting.ansdansdugiuzgguzgioansdiandwq.foo");
    }

    @Test
    public void testResolveServiceEntry() throws Exception {
        BasicAttributes records = createSrvRecords();

        when(context.getAttributes("_ldap._tcp.springsource.com", new String[] {"SRV"})).thenReturn(records);

        String hostname = dnsResolver.resolveServiceEntry("ldap", "springsource.com");
        assertEquals("kdc.springsource.com", hostname);
    }


    @Test(expected=DnsEntryNotFoundException.class)
    public void testResolveServiceEntryNotExisting() throws Exception {
        when(context.getAttributes(any(String.class), any(String[].class))).thenThrow(new NameNotFoundException("not found"));

        dnsResolver.resolveServiceEntry("wrong", "secpod.de");
    }

    @Test
    public void testResolveServiceIpAddress() throws Exception {
        BasicAttributes srvRecords = createSrvRecords();
        BasicAttributes aRecords = new BasicAttributes("A", "63.246.7.80");
        when(context.getAttributes("_ldap._tcp.springsource.com", new String[] {"SRV"})).thenReturn(srvRecords);
        when(context.getAttributes("kdc.springsource.com", new String[] {"A"})).thenReturn(aRecords);

        String ipAddress = dnsResolver.resolveServiceIpAddress("ldap", "springsource.com");
        assertEquals("63.246.7.80", ipAddress);
    }

    @Test(expected=DnsLookupException.class)
    public void testUnknowError() throws Exception {
        when(context.getAttributes(any(String.class), any(String[].class))).thenThrow(new NamingException("error"));
        dnsResolver.resolveIpAddress("");
    }



    private BasicAttributes createSrvRecords() {
        BasicAttributes records = new BasicAttributes();
        BasicAttribute record = new BasicAttribute("SRV");
        // the structure of the service records is:
        // priority weight port hostname
        // for more information: http://en.wikipedia.org/wiki/SRV_record
        record.add("20 80 389 kdc3.springsource.com.");
        record.add("10 70 389 kdc.springsource.com.");
        record.add("20 20 389 kdc4.springsource.com.");
        record.add("10 30 389 kdc2.springsource.com");
        records.put(record);
        return records;
    }
}
