package org.acegisecurity.providers.dao.ldap;

import java.util.Hashtable;
import java.util.Map;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import org.springframework.dao.DataAccessResourceFailureException;

/**
 * Convient base class and/or bean which can be used to create DirContext objects.
 * Many user's will only need to set to Url property. 
 * 
 * <p>
 * Eample: <br/>
 *  <bean id="initialDirContextFactoryBean"
 *      class="org.acegisecurity.providers.dao.ldap.InitialDirContextFactoryBean">     <br/>
 *      <property name="url"><value>ldap://myserver.com:389/</value></property>           <br/>
 *      <property name="managerUser"><value>cn=UserWithSearchPermissions,dc=mycompany,dc=com</value></property>  <br/>
 *      <property name="managerPassword"><value>PasswordForUser</value></property>        <br/>
 *  </bean>  <br/>
 * </p> 
 * 
 * 
 * @see http://java.sun.com/products/jndi/tutorial/ldap/connect/config.html
 * 
 * @author robert.sanders
 *
 */
public class InitialDirContextFactoryBean {
    
    /**
     * LDAP URL (with or without the port) of the LDAP server to connect to. 
     * <p>Example: <br/>
     *     <b>ldap://dir.mycompany.com:389/dc=mycompany,dc=com</b>  <br/>  
     *    <small>(port 389 is the standard LDAP port).  </small>
     * </p>
     */
    private String url;
        
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
    
    public InitialDirContext newInitialDirContext(String username, String password) throws AuthenticationException, DataAccessResourceFailureException {
    	Hashtable env = getEnvironment();
    	if (null != username) {
    		env.put(Context.SECURITY_PRINCIPAL, username);
    	}
    	if (null != password) {
    		env.put(Context.SECURITY_CREDENTIALS, password);
    	}
    	try {
            return new InitialDirContext(env);
    	} catch (AuthenticationException ax) {
    		throw ax;	// just pass it right on.
        } catch (NamingException nx) {
        	// any other JNDI exception:
            throw new DataAccessResourceFailureException("Unable to connect to LDAP Server; check managerUser and managerPassword.", nx);
        }
    }
    
    /** Returns a new InitialDirContext using the provided managerUser and managerPassword (if provided) as credentials. 
     * @throws AuthenticationException */
    public InitialDirContext newInitialDirContext() throws DataAccessResourceFailureException, AuthenticationException {
        return newInitialDirContext(managerUser, managerPassword);
    }
    
    /** 
     * @return The Hashtable describing the base DirContext that will be created; minus the username/password if any.
     */
    protected Hashtable getEnvironment() {
        Hashtable env = new Hashtable(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
        env.put(Context.PROVIDER_URL, url);
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
     * @return Password (if any) of the user named by the managerUser property.
     */
    public String getManagerPassword() {
        return managerPassword;
    }

    /**
     * @param managerPassword Password (if any) of the user named by the managerUser property.
     */
    public void setManagerPassword(String managerPassword) {
        this.managerPassword = managerPassword;
    }

    /**
     * @return Name of the user (typically a fully qualified DN) which 
     *   will be used to authenticate with the LDAP server when initiating LDAP connections.
     */
    public String getManagerUser() {
        return managerUser;
    }

    /**
     * For OpenLDAP this might be "cn=Manager,dc=mycompany,dc=com"; 
     *   because this user typically <b>only</b> needs to be able to search/read 
     *   the contexts against which LDAP operations occur, you may wish 
     *   to create an account with read-only settings for this purpose.
     * <p>
     *  If this property is not set, then the default behavor is 
     *  to connect to the LDAP server anonymously.
     * </p>
     * 
     * 
     * @param managerUser Name of the user (typically a fully qualified DN) which 
     *   will be used to authenticate with the LDAP server when initiating LDAP connections.
     */
    public void setManagerUser(String managerUser) {
        this.managerUser = managerUser;
    }

    /**
     * @return The URL of the LDAP host to connect to, including port (if non-default), 
     * 		and the base DN from which other operations will be relative to.
     */
    public String getUrl() {
        return url;
    }

    /**
     * LDAP URL (with or without the port) of the LDAP server to connect to. 
     * <p>Example: <br/>
     *     <b>ldap://dir.mycompany.com:389/dc=mycompany,dc=com</b>  <br/>  
     *    <small>(port 389 is the standard LDAP port) </small> so the example above could also be: <br/>
     *     <b>ldap://dir.mycompany.com/dc=mycompany,dc=com</b>  <br/>
     * </p>
     * 
     *
     * @param url The URL of the LDAP host to connect to, including port (if non-default), 
     * 		and the base DN from which other operations will be relative to. 
     */
    public void setUrl(String url) {
        this.url = url;
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
