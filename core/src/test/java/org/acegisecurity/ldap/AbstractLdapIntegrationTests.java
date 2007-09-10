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
package org.acegisecurity.ldap;

import org.springframework.test.AbstractDependencyInjectionSpringContextTests;
import org.springframework.ldap.core.ContextSource;
import org.springframework.core.io.ClassPathResource;

import java.io.File;

/**
 * Based on class borrowed from Spring Ldap project.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractLdapIntegrationTests extends AbstractDependencyInjectionSpringContextTests {
    private LdapServerManager ldapServerManager;
    private ContextSource contextSource;
    private DefaultInitialDirContextFactory initialDirContextFactory;

    protected AbstractLdapIntegrationTests() {
        super.setAutowireMode(AUTOWIRE_BY_NAME);
    }

    protected String[] getConfigLocations() {
        return new String[] {"/org/acegisecurity/ldap/ldapIntegrationTestContext.xml"};
    }


    protected void onSetUp() throws Exception {
        super.onSetUp();

        ClassPathResource ldifs = new ClassPathResource("org/acegisecurity/ldap/setup_data.ldif");

        ldapServerManager.cleanAndSetup(ldifs.getFile().getAbsolutePath());
    }

    public void setLdapServerManager(LdapServerManager ldapServerManager) {
        this.ldapServerManager = ldapServerManager;
    }

    public ContextSource getContextSource() {
        return contextSource;
    }

    public void setContextSource(ContextSource contextSource) {
        this.contextSource = contextSource;
    }

    /**
     * We have both a context source and intitialdircontextfactory. The former is also used in
     * the cleanAndSetup method so any mods during tests can mess it up.
     * TODO: Once the initialdircontextfactory stuff has been refactored, revisit this and remove this property.
     */
    public DefaultInitialDirContextFactory getInitialDirContextFactory() {
        return initialDirContextFactory;
    }

    public void setInitialDirContextFactory(DefaultInitialDirContextFactory initialDirContextFactory) {
        this.initialDirContextFactory = initialDirContextFactory;
    }
}
