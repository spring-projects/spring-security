/*
 * Copyright 2005-2007 the original author or authors.
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

package org.acegisecurity.ldap;

import java.util.Properties;

import javax.naming.Binding;
import javax.naming.Context;
import javax.naming.ContextNotEmptyException;
import javax.naming.InitialContext;
import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.NameNotFoundException;
import javax.naming.directory.DirContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.server.core.configuration.ShutdownConfiguration;
import org.apache.directory.server.jndi.ServerContextFactory;
import org.apache.directory.server.protocol.shared.store.LdifFileLoader;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.DefaultDirObjectFactory;


/**
 * Utility class to initialize the apache directory server for use in the integration tests.
 *
 * @author Mattias Arthursson
 * @author Luke Taylor (borrowed from Spring Ldap project).
 *
 */
public class LdapServerManager implements DisposableBean {
    private static Log log = LogFactory.getLog(LdapServerManager.class);

    private ContextSource contextSource;

    public void setContextSource(ContextSource contextSource) {
        this.contextSource = contextSource;
    }

    public void destroy() throws Exception {
        Properties env = new Properties();
        env.setProperty(Context.INITIAL_CONTEXT_FACTORY,
                ServerContextFactory.class.getName());
        env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
        env.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.setProperty(Context.SECURITY_CREDENTIALS, "secret");

        ShutdownConfiguration configuration = new ShutdownConfiguration();
        env.putAll(configuration.toJndiEnvironment());

        new InitialContext(env);
    }

    public void cleanAndSetup(String ldifFile) throws Exception {
        DirContext ctx = contextSource.getReadWriteContext();

        // First of all, make sure the database is empty.
        Name startingPoint = null;

        // Different test cases have different base paths. This means that the
        // starting point will be different.
        if (ctx.getEnvironment().get(
                DefaultDirObjectFactory.JNDI_ENV_BASE_PATH_KEY) != null) {
            startingPoint = DistinguishedName.EMPTY_PATH;
        } else {
            startingPoint = new DistinguishedName("dc=acegisecurity,dc=org");
        }

        try {
            log.info("Cleaning all present data.");
            clearSubContexts(ctx, startingPoint);
            // Load the ldif to the recently started server
            log.info("Loading setup data");
            LdifFileLoader loader = new LdifFileLoader(ctx, ldifFile);
            loader.execute();
        } finally {
            ctx.close();
        }
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
            } catch (Exception e) {
                // Never mind this
            }
        }
    }
}

