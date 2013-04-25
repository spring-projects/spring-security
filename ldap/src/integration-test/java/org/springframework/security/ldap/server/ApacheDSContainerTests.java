package org.springframework.security.ldap.server;

import static junit.framework.Assert.fail;

import org.apache.directory.shared.ldap.name.LdapDN;
import org.junit.Test;

/**
 * Useful for debugging the container by itself.
 *
 * @author Luke Taylor
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
}
