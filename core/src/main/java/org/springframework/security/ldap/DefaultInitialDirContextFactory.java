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

import org.springframework.security.AcegiMessageSource;
import org.springframework.security.BadCredentialsException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;

import org.springframework.util.Assert;
import org.springframework.ldap.UncategorizedLdapException;
import org.springframework.ldap.core.support.DefaultDirObjectFactory;
import org.springframework.dao.DataAccessException;

import java.util.Hashtable;
import java.util.Map;
import java.util.StringTokenizer;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;


/**
 * Encapsulates the information for connecting to an LDAP server and provides an access point for obtaining
 * <tt>DirContext</tt> references.
 * <p>
 * The directory location is configured using by setting the constructor argument
 * <tt>providerUrl</tt>. This should be in the form <tt>ldap://monkeymachine.co.uk:389/dc=acegisecurity,dc=org</tt>.
 * The Sun JNDI provider also supports lists of space-separated URLs, each of which will be tried in turn until a
 * connection is obtained.
 * </p>
 *  <p>To obtain an initial context, the client calls the <tt>newInitialDirContext</tt> method. There are two
 * signatures - one with no arguments and one which allows binding with a specific username and password.
 * </p>
 *  <p>The no-args version will bind anonymously unless a manager login has been configured using the properties
 * <tt>managerDn</tt> and <tt>managerPassword</tt>, in which case it will bind as the manager user.</p>
 *  <p>Connection pooling is enabled by default for anonymous or manager connections, but not when binding as a
 * specific user.</p>
 *
 * @author Robert Sanders
 * @author Luke Taylor
 * @version $Id$
 *
 * @see <a href="http://java.sun.com/products/jndi/tutorial/ldap/connect/pool.html">The Java tutorial's guide to LDAP
 *      connection pooling</a>
 */
public class DefaultInitialDirContextFactory implements InitialDirContextFactory, MessageSourceAware {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(DefaultInitialDirContextFactory.class);
    private static final String CONNECTION_POOL_KEY = "com.sun.jndi.ldap.connect.pool";
    private static final String AUTH_TYPE_NONE = "none";

    //~ Instance fields ================================================================================================

    /** Allows extra environment variables to be added at config time. */
    private Map extraEnvVars = null;
    protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();

    /** Type of authentication within LDAP; default is simple. */
    private String authenticationType = "simple";

    /**
     * The INITIAL_CONTEXT_FACTORY used to create the JNDI Factory. Default is
     * "com.sun.jndi.ldap.LdapCtxFactory"; you <b>should not</b> need to set this unless you have unusual needs.
     */
    private String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";

    private String dirObjectFactoryClass = DefaultDirObjectFactory.class.getName();

    /**
     * If your LDAP server does not allow anonymous searches then you will need to provide a "manager" user's
     * DN to log in with.
     */
    private String managerDn = null;

    /** The manager user's password. */
    private String managerPassword = "manager_password_not_set";

    /** The LDAP url of the server (and root context) to connect to. */
    private String providerUrl;

    /**
     * The root DN. This is worked out from the url. It is used by client classes when forming a full DN for
     * bind authentication (for example).
     */
    private String rootDn = null;

    /**
     * Use the LDAP Connection pool; if true, then the LDAP environment property
     * "com.sun.jndi.ldap.connect.pool" is added to any other JNDI properties.
     */
    private boolean useConnectionPool = true;

    /** Set to true for ldap v3 compatible servers */
    private boolean useLdapContext = false;

    //~ Constructors ===================================================================================================

    /**
     * Create and initialize an instance to the LDAP url provided
     *
     * @param providerUrl a String of the form <code>ldap://localhost:389/base_dn<code>
     */
    public DefaultInitialDirContextFactory(String providerUrl) {
        this.setProviderUrl(providerUrl);
    }

    //~ Methods ========================================================================================================

    /**
     * Set the LDAP url
     *
     * @param providerUrl a String of the form <code>ldap://localhost:389/base_dn<code>
     */
    private void setProviderUrl(String providerUrl) {
        Assert.hasLength(providerUrl, "An LDAP connection URL must be supplied.");

        this.providerUrl = providerUrl;

        StringTokenizer st = new StringTokenizer(providerUrl);

        // Work out rootDn from the first URL and check that the other URLs (if any) match
        while (st.hasMoreTokens()) {
            String url = st.nextToken();
            String urlRootDn = LdapUtils.parseRootDnFromUrl(url);

            logger.info(" URL '" + url + "', root DN is '" + urlRootDn + "'");

            if (rootDn == null) {
                rootDn = urlRootDn;
            } else if (!rootDn.equals(urlRootDn)) {
                throw new IllegalArgumentException("Root DNs must be the same when using multiple URLs");
            }
        }

        // This doesn't necessarily hold for embedded servers.
        //Assert.isTrue(uri.getScheme().equals("ldap"), "Ldap URL must start with 'ldap://'");
    }

    /**
     * Get the LDAP url
     *
     * @return the url
     */
    private String getProviderUrl() {
        return providerUrl;
    }

    private InitialDirContext connect(Hashtable env) {
        if (logger.isDebugEnabled()) {
            Hashtable envClone = (Hashtable) env.clone();

            if (envClone.containsKey(Context.SECURITY_CREDENTIALS)) {
                envClone.put(Context.SECURITY_CREDENTIALS, "******");
            }

            logger.debug("Creating InitialDirContext with environment " + envClone);
        }

        try {
            return useLdapContext ? new InitialLdapContext(env, null) : new InitialDirContext(env);
        } catch (NamingException ne) {
            if ((ne instanceof javax.naming.AuthenticationException)
                    || (ne instanceof OperationNotSupportedException)) {
                throw new BadCredentialsException(messages.getMessage("DefaultIntitalDirContextFactory.badCredentials",
                        "Bad credentials"), ne);
            }

            if (ne instanceof CommunicationException) {
                throw new UncategorizedLdapException(messages.getMessage(
                        "DefaultIntitalDirContextFactory.communicationFailure", "Unable to connect to LDAP server"), ne);
            }

            throw new UncategorizedLdapException(messages.getMessage(
                    "DefaultIntitalDirContextFactory.unexpectedException",
                    "Failed to obtain InitialDirContext due to unexpected exception"), ne);
        }
    }

    /**
     * Sets up the environment parameters for creating a new context.
     *
     * @return the Hashtable describing the base DirContext that will be created, minus the username/password if any.
     */
    protected Hashtable getEnvironment() {
        Hashtable env = new Hashtable();

        env.put(Context.SECURITY_AUTHENTICATION, authenticationType);
        env.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
        env.put(Context.PROVIDER_URL, getProviderUrl());

        if (useConnectionPool) {
            env.put(CONNECTION_POOL_KEY, "true");
        }

        if ((extraEnvVars != null) && (extraEnvVars.size() > 0)) {
            env.putAll(extraEnvVars);
        }

        return env;
    }

    /**
     * Returns the root DN of the configured provider URL. For example, if the URL is
     * <tt>ldap://monkeymachine.co.uk:389/dc=acegisecurity,dc=org</tt> the value will be
     * <tt>dc=acegisecurity,dc=org</tt>.
     *
     * @return the root DN calculated from the path of the LDAP url.
     */
    public String getRootDn() {
        return rootDn;
    }

    /**
     * Connects anonymously unless a manager user has been specified, in which case it will bind as the
     * manager.
     *
     * @return the resulting context object.
     */
    public DirContext newInitialDirContext() {
        if (managerDn != null) {
            return newInitialDirContext(managerDn, managerPassword);
        }

        Hashtable env = getEnvironment();
        env.put(Context.SECURITY_AUTHENTICATION, AUTH_TYPE_NONE);

        return connect(env);
    }

    public DirContext newInitialDirContext(String username, String password) {
        Hashtable env = getEnvironment();

        // Don't pool connections for individual users
        if (!username.equals(managerDn)) {
            env.remove(CONNECTION_POOL_KEY);
        }

        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);

        if(dirObjectFactoryClass != null) {
            env.put(Context.OBJECT_FACTORIES, dirObjectFactoryClass);
        }

        return connect(env);
    }

    /** Spring LDAP <tt>ContextSource</tt> method */
    public DirContext getReadOnlyContext() throws DataAccessException {
        return newInitialDirContext();
    }

    /** Spring LDAP <tt>ContextSource</tt> method */
    public DirContext getReadWriteContext() throws DataAccessException {
        return newInitialDirContext();
    }

    public void setAuthenticationType(String authenticationType) {
        Assert.hasLength(authenticationType, "LDAP Authentication type must not be empty or null");
        this.authenticationType = authenticationType;
    }

    /**
     * Sets any custom environment variables which will be added to the those returned
     * by the <tt>getEnvironment</tt> method.
     *
     * @param extraEnvVars extra environment variables to be added at config time.
     */
    public void setExtraEnvVars(Map extraEnvVars) {
        Assert.notNull(extraEnvVars, "Extra environment map cannot be null.");
        this.extraEnvVars = extraEnvVars;
    }

    public void setInitialContextFactory(String initialContextFactory) {
        Assert.hasLength(initialContextFactory, "Initial context factory name cannot be empty or null");
        this.initialContextFactory = initialContextFactory;
    }

    /**
     * Sets the directory user to authenticate as when obtaining a context using the
     * <tt>newInitialDirContext()</tt> method.
     * If no name is supplied then the context will be obtained anonymously.
     *
     * @param managerDn The name of the "manager" user for default authentication.
     */
    public void setManagerDn(String managerDn) {
        Assert.hasLength(managerDn, "Manager user name  cannot be empty or null.");
        this.managerDn = managerDn;
    }

    /**
     * Sets the password which will be used in combination with the manager DN.
     *
     * @param managerPassword The "manager" user's password.
     */
    public void setManagerPassword(String managerPassword) {
        Assert.hasLength(managerPassword, "Manager password must not be empty or null.");
        this.managerPassword = managerPassword;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    /**
     * Connection pooling is enabled by default for anonymous or "manager" connections when using the default
     * Sun provider. To disable all connection pooling, set this property to false.
     *
     * @param useConnectionPool whether to pool connections for non-specific users.
     */
    public void setUseConnectionPool(boolean useConnectionPool) {
        this.useConnectionPool = useConnectionPool;
    }

    public void setUseLdapContext(boolean useLdapContext) {
        this.useLdapContext = useLdapContext;
    }

    public void setDirObjectFactory(String dirObjectFactory) {
        this.dirObjectFactoryClass = dirObjectFactory;
    }
}
