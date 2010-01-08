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
 */
public abstract class AbstractLdapIntegrationTests {
//    private static InMemoryXmlApplicationContext appContext;
    private static ApacheDSContainer server;
    private static BaseLdapPathContextSource contextSource;

    protected AbstractLdapIntegrationTests() {
    }

    @BeforeClass
    public static void startServer() throws Exception {
        contextSource = new DefaultSpringSecurityContextSource("ldap://127.0.0.1:53389/dc=springframework,dc=org");
        ((DefaultSpringSecurityContextSource)contextSource).afterPropertiesSet();
        server = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
        server.afterPropertiesSet();
    }

    @AfterClass
    public static void stopServer() throws Exception {
        if (server != null) {
            server.stop();
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
            LdifFileLoader loader = new LdifFileLoader(server.getService().getAdminSession(), ldifs.getFile().getAbsolutePath());
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
