/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.providers.ldap;

import java.util.Hashtable;
import java.util.Map;
import java.net.URI;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.CommunicationException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.DirContext;

import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.acegisecurity.BadCredentialsException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Encapsulates the information for connecting to an LDAP server and provides an
 * access point for obtaining <tt>DirContext</tt> references.
 * <p>
 * The directory location is configured using by setting the <tt>url</tt> property.
 * This should be in the form <tt>ldap://monkeymachine.co.uk:389/dc=acegisecurity,dc=org</tt>.
 * </p>
 * <p>
 * To obtain an initial context, th client calls the <tt>newInitialDirContext</tt>
 * method. There are two signatures - one with no arguments and one which allows
 * binding with a specific username and password.
 * </p>
 * <p>
 * The no-args version will bind anonymously or if a manager login has been configured
 * using the properties <tt>managerDn</tt> and <tt>managerPassword</tt> it will bind as
 * that user.
 * </p>
 * <p>
 * Connection pooling is enabled for anonymous or manager connections, but not when binding
 * as a specific user.
 * </p>
 *
 * @see <a href="http://java.sun.com/products/jndi/tutorial/ldap/connect/pool.html">The Java tutorial's guide to
 * Connection Pooling</a>
 *
 * @author Robert Sanders
 * @author Luke Taylor
 * @version $Id$
 *
 */
public class DefaultInitialDirContextFactory implements InitialDirContextFactory,
    InitializingBean {
    
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(DefaultInitialDirContextFactory.class);

    private static final String CONNECTION_POOL_KEY = "com.sun.jndi.ldap.connect.pool";

    private static final String AUTH_TYPE_NONE = "none";

    //~ Instance fields ========================================================

    /**
     * The LDAP url of the server (and root context) to connect to.
     * TODO: Allow a backup URL for a replication server.
     */
    private String url;

    /**
     * The root DN. This is worked out from the url.
     * It is used by client classes when forming a full DN for
     * bind authentication (for example).
     */
    private String rootDn;

    /**
     * If your LDAP server does not allow anonymous searches then
     * you will need to provide a "manager" user's DN to log in with.
     */
    private String managerDn = null;

    /**
     * The manager user's password.
     */
    private String managerPassword = null;

    /** Type of authentication within LDAP; default is simple. */
    private String authenticationType = "simple";

    /**
     * The INITIAL_CONTEXT_FACTORY used to create the JNDI Factory.
     * Default is "com.sun.jndi.ldap.LdapCtxFactory"; you <b>should not</b>
     * need to set this unless you have unusual needs.
     */
    private String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";

    /** Allows extra environment variables to be added at config time. */
    private Map extraEnvVars = null;

    /**
     * Use the LDAP Connection pool; if true, then the
     * LDAP environment property "com.sun.jndi.ldap.connect.pool" is added
     * to any other JNDI properties.
     */
    private boolean useConnectionPool = true;    

    //~ Methods ================================================================

    /**
     * Connects anonymously unless a manager user has been specified, in which case
     * it will bind as the manager.
     *
     * @return the resulting
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
        if(!username.equals(managerDn)) {
            env.remove(CONNECTION_POOL_KEY);
        }

        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);

        return connect(env);
    }

    /**
     * @return The Hashtable describing the base DirContext that will be created, minus the username/password if any.
     */
    protected Hashtable getEnvironment() {
        Hashtable env = new Hashtable();

        env.put(Context.SECURITY_AUTHENTICATION, authenticationType);
        env.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
        env.put(Context.PROVIDER_URL, url);

        if (useConnectionPool) {
            env.put(CONNECTION_POOL_KEY, "true");
        }

        if ((extraEnvVars != null) && (extraEnvVars.size() > 0)) {
            env.putAll(extraEnvVars);
        }

        return env;
    }

    private InitialDirContext connect(Hashtable env) {
        
// Prints the password, so don't use except for debugging.
//        logger.debug("Creating initial context with env " + env);

        try {
            return new InitialDirContext(env);

        } catch(CommunicationException ce) {
            throw new DataAccessResourceFailureException("Unable to connect to LDAP Server.", ce);
        } catch(javax.naming.AuthenticationException ae) {
            throw new BadCredentialsException("Authentication to LDAP server failed.", ae);
        } catch (NamingException nx) {
            throw new LdapDataAccessException("Failed to obtain InitialDirContext", nx);
        }
    }

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(url, "An LDAP connection URL must be supplied.");

        if(url.startsWith("ldap:")) {

            URI uri = new URI(url);

            rootDn = uri.getPath();
        } else {
            // Assume it's an embedded server
            rootDn = url;
        }

        if(rootDn.startsWith("/")) {
            rootDn = rootDn.substring(1);
        }

        //Assert.isTrue(uri.getScheme().equals("ldap"), "Ldap URL must start with 'ldap://'");

    }

    /**
     * Returns the root DN of the configured provider URL. For example,
     * if the URL is <tt>ldap://monkeymachine.co.uk:389/dc=acegisecurity,dc=org</tt>
     * the value will be <tt>dc=acegisecurity,dc=org</tt>.
     *
     * @return the root DN calculated from the path of the LDAP url.
     */
    public String getRootDn() {
        return rootDn;
    }

    public void setAuthenticationType(String authenticationType) {
        Assert.hasLength(authenticationType);
        this.authenticationType = authenticationType;
    }

    public void setInitialContextFactory(String initialContextFactory) {
        Assert.hasLength(initialContextFactory);
        this.initialContextFactory = initialContextFactory;
    }

    /**
     * @param managerDn The name of the "manager" user for default authentication.
     */
    public void setManagerDn(String managerDn) {
        this.managerDn = managerDn;
    }

    /**
     * @param managerPassword The "manager" user's password.
     */
    public void setManagerPassword(String managerPassword) {
        this.managerPassword = managerPassword;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * @param extraEnvVars extra environment variables to be added at config time.
     */
    public void setExtraEnvVars(Map extraEnvVars) {
        this.extraEnvVars = extraEnvVars;
    }

}
