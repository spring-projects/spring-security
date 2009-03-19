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

import javax.naming.Binding;
import javax.naming.ContextNotEmptyException;
import javax.naming.Name;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.protocol.shared.store.LdifFileLoader;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.springframework.core.io.ClassPathResource;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.config.BeanIds;
import org.springframework.security.util.InMemoryXmlApplicationContext;

/**
 * Based on class borrowed from Spring Ldap project.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractLdapIntegrationTests {
    private static InMemoryXmlApplicationContext appContext;

    protected AbstractLdapIntegrationTests() {
    }

    @BeforeClass
    public static void loadContext() throws NamingException {
        shutdownRunningServers();
        appContext = new InMemoryXmlApplicationContext("<ldap-server port='53389' ldif='classpath:test-server.ldif'/>");

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


    @After
    public final void reloadServerDataIfDirty() throws Exception {
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

    public BaseLdapPathContextSource getContextSource() {
        return (BaseLdapPathContextSource)appContext.getBean(BeanIds.CONTEXT_SOURCE);
    }


    private void clearSubContexts(DirContext ctx, Name name) throws NamingException {

        NamingEnumeration<Binding> enumeration = null;
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
