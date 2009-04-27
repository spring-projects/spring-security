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

import java.util.HashSet;
import java.util.Set;

import javax.naming.Binding;
import javax.naming.ContextNotEmptyException;
import javax.naming.Name;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

import org.apache.directory.server.configuration.MutableServerStartupConfiguration;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.partition.impl.btree.MutableBTreePartitionConfiguration;
import org.apache.directory.server.protocol.shared.store.LdifFileLoader;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.springframework.core.io.ClassPathResource;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;

/**
 * Based on class borrowed from Spring Ldap project.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractLdapIntegrationTests {
//    private static InMemoryXmlApplicationContext appContext;
    private static ApacheDSContainer server;
    private static BaseLdapPathContextSource contextSource;

    protected AbstractLdapIntegrationTests() {
    }

    @SuppressWarnings("unchecked")
    @BeforeClass
    public static void startServer() throws Exception {
        shutdownRunningServers();
        MutableBTreePartitionConfiguration partition =  new MutableBTreePartitionConfiguration();
        partition.setName("springsecurity");

        Attributes rootAttributes = new BasicAttributes("dc", "springsecurity");
        Attribute a = new BasicAttribute("objectClass");
        a.add("top");
        a.add("domain");
        a.add("extensibleObject");
        rootAttributes.put(a);

        partition.setContextEntry(rootAttributes);
        partition.setSuffix("dc=springframework,dc=org");

        Set partitions = new HashSet();
        partitions.add(partition);

        MutableServerStartupConfiguration cfg = new MutableServerStartupConfiguration();
        cfg.setLdapPort(53389);
        cfg.setShutdownHookEnabled(false);
        cfg.setExitVmOnShutdown(false);
        cfg.setContextPartitionConfigurations(partitions);

        contextSource = new DefaultSpringSecurityContextSource("ldap://127.0.0.1:53389/dc=springframework,dc=org");
        ((DefaultSpringSecurityContextSource)contextSource).afterPropertiesSet();
        server = new ApacheDSContainer(cfg, contextSource, "classpath:test-server.ldif");
        server.afterPropertiesSet();
    }

    @AfterClass
    public static void stopServer() throws Exception {
        if (server != null) {
            server.stop();
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
        return contextSource;
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
