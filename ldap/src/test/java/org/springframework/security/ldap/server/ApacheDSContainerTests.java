package org.springframework.security.ldap.server;

import org.apache.directory.shared.ldap.name.LdapDN;
import org.junit.Test;

/**
 * Useful for debugging the container by itself.
 *
 * @author Luke Taylor
 * @version $Id$
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
}
