package net.sf.acegisecurity.providers.dao.ldap;

import java.util.Hashtable;
import java.util.Map;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import org.springframework.dao.DataAccessResourceFailureException;

/**
 * @see http://java.sun.com/products/jndi/tutorial/ldap/connect/config.html
 * 
 * @author robert.sanders
 *
 */
public class LdapSupport {
    
    /**
     * LDAP URL (without the port) of the LDAP server to connect to; example
     * <b>ldap://dir.mycompany.com:389/</b>  (port 389 is the standard LDAP port).
     */
    private String URL;
    
    /** Root context of the LDAP Connection, if any is needed.  
     *  <p> Example: <b>dc=mycompany,dc=com</b> </p> 
     *  <p><strong>Note: </strong> It is usually preferable to add this data as part of the 
     *      userContexts and/or roleContexts attributes. </p> 
     **/
    private String rootContext = "";
    
    /** Internal state: URL + rootContext.  */
    private String initialContextURL;
    
    /** If your LDAP server does not allow anonymous searches then 
     *  you will need to provide a username with which to login with;
     *  this is that username.
     */
    private String managerUser;
    
    /** If your LDAP server does not allow anonymous searches then 
     *  you will need to provide a username with which to login with;
     *  this is the password of that user.
     */
    private String managerPassword;
    
    /** Type of authentication within LDAP; default is simple. */
    private String authenticationType = "simple";
    
    /** The INITIAL_CONTEXT_FACTORY used to create the JNDI Factory.
     *  Default is "com.sun.jndi.ldap.LdapCtxFactory"; you <b>should not</b>
     *  need to set this unless you have unusual needs.
     **/
    private String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";

    /** Allows extra environment variables to be added at config time. */
    private Map extraEnvVars = null;
    
    /** Use the LDAP Connection pool (in SUN JVMs)?; if true, then the 
     *  LDAP environment property "com.sun.jndi.ldap.connect.pool" is added 
     *  to any other JNDI properties. 
     *  @see http://java.sun.com/products/jndi/tutorial/ldap/connect/pool.html 
     *  @see http://java.sun.com/products/jndi/tutorial/ldap/connect/config.html
     */
    private boolean connectionPoolEnabled = true;
    
    public InitialDirContext getInitialContext() throws DataAccessResourceFailureException {
        Hashtable env = getEnvironment();
        if (managerUser != null) {
            env.put(Context.SECURITY_PRINCIPAL, managerUser);
            env.put(Context.SECURITY_CREDENTIALS, managerPassword);
        }
        try {
            return new InitialDirContext(env);
        } catch (NamingException nx) {
            throw new DataAccessResourceFailureException("Unable to connect to LDAP Server; check managerUser and managerPassword.", nx);
        }
    }
    
    /** 
     * @return The Hashtable describing the base DirContext that will be created; minus the username/password if any.
     */
    protected Hashtable getEnvironment() {
        Hashtable env = new Hashtable(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
        env.put(Context.PROVIDER_URL, getInitialContextURL());
        env.put(Context.SECURITY_AUTHENTICATION, authenticationType);
        if (connectionPoolEnabled) {
            env.put("com.sun.jndi.ldap.connect.pool", "true");
        }
        if ((extraEnvVars != null) && (extraEnvVars.size() > 0)) {
            env.putAll(extraEnvVars);
        }
        return env;
    }
    
    /** 
     * @return The full URL for the LDAP source for use in creating the InitialContext; it should look 
     *      something like:  ldap://www.mycompany.com:389/dc=company,dc=com
     */
    public synchronized String getInitialContextURL() {
        if (null == this.initialContextURL) {
            StringBuffer initialContextURL = new StringBuffer( this.URL );
            if (!this.URL.endsWith("/")) {
                initialContextURL.append("/");
            }
            initialContextURL.append(this.rootContext);
            this.initialContextURL = initialContextURL.toString();
        }
        return this.initialContextURL;
    }
    
    /**
     * @return Returns the authenticationType.
     */
    public String getAuthenticationType() {
        return authenticationType;
    }

    /**
     * @param authenticationType The authenticationType to set.
     */
    public void setAuthenticationType(String authenticationType) {
        this.authenticationType = authenticationType;
    }

    /**
     * @return Returns the initialContextFactory.
     */
    public String getInitialContextFactory() {
        return initialContextFactory;
    }

    /**
     * @param initialContextFactory The initialContextFactory to set.
     */
    public void setInitialContextFactory(String initialContextFactory) {
        this.initialContextFactory = initialContextFactory;
    }

    /**
     * @return Returns the managerPassword.
     */
    public String getManagerPassword() {
        return managerPassword;
    }

    /**
     * @param managerPassword The managerPassword to set.
     */
    public void setManagerPassword(String managerPassword) {
        this.managerPassword = managerPassword;
    }

    /**
     * @return Returns the managerUser.
     */
    public String getManagerUser() {
        return managerUser;
    }

    /**
     * @param managerUser The managerUser to set.
     */
    public void setManagerUser(String managerUser) {
        this.managerUser = managerUser;
    }

    /**
     * @return Returns the rootContext.
     */
    public String getRootContext() {
        return rootContext;
    }

    /**
     * @param rootContext The rootContext to set.
     */
    public void setRootContext(String rootContext) {
        this.rootContext = rootContext;
    }

    /**
     * @return Returns the uRL.
     */
    public String getURL() {
        return URL;
    }

    /**
     * @param url The uRL to set.
     */
    public void setURL(String url) {
        URL = url;
    }

    /**
     * @return Allows extra environment variables to be added at config time.
     */
    public Map getExtraEnvVars() {
        return extraEnvVars;
    }

    /**
     * @param extraEnvVars Allows extra environment variables to be added at config time.
     */
    public void setExtraEnvVars(Map extraEnvVars) {
        this.extraEnvVars = extraEnvVars;
    }
    
}
