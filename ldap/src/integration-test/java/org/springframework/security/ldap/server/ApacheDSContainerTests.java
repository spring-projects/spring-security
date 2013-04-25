/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.ldap.server;

import static junit.framework.Assert.fail;

import org.apache.directory.shared.ldap.name.LdapDN;
import org.junit.Test;

/**
 * Useful for debugging the container by itself.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 */
public class ApacheDSContainerTests {

    @Test
    public void successfulStartupAndShutdown() throws Exception {
        LdapDN people = new LdapDN("ou=people,dc=springframework,dc=org");
        people.toString();

//        ApacheDSContainer server = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
//        server.afterPropertiesSet();
//
//        server.getService().getAdminSession().lookup(people);
//
//        server.stop();
    }

    // SEC-2162
    @Test
    public void failsToStartThrowsException() throws Exception {
        ApacheDSContainer server1 = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
        ApacheDSContainer server2 = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
        try {
            server1.afterPropertiesSet();
            try {
                server2.afterPropertiesSet();
                fail("Expected Exception");
            } catch(RuntimeException success) {}
        } finally {
            try {
                server1.destroy();
            }catch(Throwable t) {}
            try {
                server2.destroy();
            }catch(Throwable t) {}
        }
    }

    // SEC-2161
    @Test
    public void multipleInstancesSimultanciously() throws Exception {
        ApacheDSContainer server1 = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
        ApacheDSContainer server2 = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
        try {
            server1.afterPropertiesSet();
            server2.afterPropertiesSet();
        } finally {
            try {
                server1.destroy();
            }catch(Throwable t) {}
            try {
                server2.destroy();
            }catch(Throwable t) {}
        }
    }
}
