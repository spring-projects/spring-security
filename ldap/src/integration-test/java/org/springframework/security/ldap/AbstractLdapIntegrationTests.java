/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.ldap;

import org.junit.*;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;

/**
 * @author Luke Taylor
 */
public abstract class AbstractLdapIntegrationTests {
    private static DefaultSpringSecurityContextSource contextSource;

    @BeforeClass
    public static void createContextSource() throws Exception {
        contextSource = new DefaultSpringSecurityContextSource("ldap://127.0.0.1:53389/dc=springframework,dc=org");
// OpenLDAP configuration
//        contextSource = new DefaultSpringSecurityContextSource("ldap://127.0.0.1:22389/dc=springsource,dc=com");
//        contextSource.setUserDn("cn=admin,dc=springsource,dc=com");
//        contextSource.setPassword("password");
        contextSource.afterPropertiesSet();
    }

    public BaseLdapPathContextSource getContextSource() {
        return contextSource;
    }

}
