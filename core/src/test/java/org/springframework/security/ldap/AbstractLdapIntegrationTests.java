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

import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.core.io.ClassPathResource;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.junit.BeforeClass;
import org.junit.Before;
import org.junit.AfterClass;
import org.junit.After;
import org.apache.directory.server.protocol.shared.store.LdifFileLoader;
import org.apache.directory.server.core.DirectoryService;

import javax.naming.directory.DirContext;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;
import javax.naming.Binding;
import javax.naming.ContextNotEmptyException;
import javax.naming.NameNotFoundException;
import java.util.Set;

/**
 * Based on class borrowed from Spring Ldap project.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractLdapIntegrationTests {
    private static ClassPathXmlApplicationContext appContext;
    private boolean dirty = false;

    protected AbstractLdapIntegrationTests() {
    }

    @BeforeClass
    public static void loadContext() throws NamingException {
        shutdownRunningServers();
        appContext = new ClassPathXmlApplicationContext("/org/springframework/security/ldap/ldapIntegrationTestContext.xml");

    }

    @AfterClass
    public static void closeContext() throws Exception {
        if(appContext != null) {
            appContext.close();
        }
        shutdownRunningServers();
    }

    private static void shutdownRunningServers() throws NamingException {
        DirectoryService ds = DirectoryService.getInstance();

        if (ds.isStarted()) {
            System.out.println("WARNING: Discovered running DirectoryService with configuration: " + ds.getConfiguration().getStartupConfiguration().toString());
            System.out.println("Shutting it down...");
            ds.shutdown();
        }
    }


    @Before
    public void onSetUp() throws Exception {
    }

    /** Reloads the server data file */
    protected void setDirty() {
        dirty = true;
    }

    @After
    public final void reloadServerDataIfDirty() throws Exception {
//        if (!dirty) {
//            return;
//        }

//        closeContext();
//        loadContext();
        ClassPathResource ldifs = new ClassPathResource("test-server.ldif");

        if (!ldifs.getFile().exists()) {
            throw new IllegalStateException("Ldif file not found: " + ldifs.getFile().getAbsolutePath());
        }

        DirContext ctx = getContextSource().getReadWriteContext();

        // First of all, make sure the database is empty.
        Name startingPoint = new DistinguishedName("dc=springframework,dc=org");

        try {
            clearSubContexts(ctx, startingPoint);
            LdifFileLoader loader = new LdifFileLoader(ctx, ldifs.getFile().getAbsolutePath());
            loader.execute();
        } finally {
            ctx.close();
        }
    }

    public SpringSecurityContextSource getContextSource() {
        return (SpringSecurityContextSource) appContext.getBean("contextSource");
    }

    /**
     * We have both a context source and intitialdircontextfactory. The former is also used in
     * the cleanAndSetup method so any mods during tests can mess it up.
     * TODO: Once the initialdircontextfactory stuff has been refactored, revisit this and remove this property.
     */
    protected DefaultInitialDirContextFactory getInitialDirContextFactory() {
        return (DefaultInitialDirContextFactory) appContext.getBean("initialDirContextFactory");
    }

    private void clearSubContexts(DirContext ctx, Name name) throws NamingException {

        NamingEnumeration enumeration = null;
        try {
            enumeration = ctx.listBindings(name);
            while (enumeration.hasMore()) {
                Binding element = (Binding) enumeration.next();
                DistinguishedName childName = new DistinguishedName(element.getName());
                childName.prepend((DistinguishedName) name);

                try {
                    ctx.destroySubcontext(childName);
                } catch (ContextNotEmptyException e) {
                    clearSubContexts(ctx, childName);
                    ctx.destroySubcontext(childName);
                }
            }
        } catch(NameNotFoundException ignored) {
        }
        catch (NamingException e) {
            e.printStackTrace();
        } finally {
            try {
                enumeration.close();
            } catch (Exception ignored) {
            }
        }
    }
}
