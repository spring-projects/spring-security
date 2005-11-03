package net.sf.acegisecurity.providers.dao.ldap;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;

import javax.naming.AuthenticationException;
import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;

import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.dao.User;

/** 
 * A much simplified (vs the 1.6 revision) LdapPasswordAuthenticationDao, 
 * which should meet all 'basic' needs, leaving advanced options such as 
 * multiple user and/or role contexts.  This version assumes all users 
 * are in one context, and roles are assigned via attributes of the user's 
 * directory object.  Authentication is done by creating a username for 
 * <br/><br/>
 * 
 * <h4>Examples:</h4>
 * <p>The following examples would be linked into the main Acegi 
 *    configuration by: <br/>
 *    <bean id="passwordAuthenticationProvider" 
 *       class="net.sf.acegisecurity.providers.dao.PasswordDaoAuthenticationProvider">   <br/>
 *       <property name="passwordAuthenticationDao">                                     <br/>
 *         <ref bean="passwordAuthenticationDao"/>                                       <br/>
 *       </property>                                                                     <br/>
 *    </bean>                                                                            <br/>
 * </p>
 * 
 * <h5 title="as seen in the Unit tests">'Standard' LDAP Settings</h5>
 * <p>
 *   <bean id="passwordAuthenticationDao"
 *       class="net.sf.acegisecurity.providers.dao.ldap.LdapPasswordAuthenticationDao">      <br/>
 *       <property name="url"><value>ldap://localhost:389/ou=system</value></property>      <br/>
 *       <property name="usernameFormat"><value>uid={0},ou=users,ou=system</value></property>      <br/>
 *       <property name="userLookupNameFormat"><value>uid={0},ou=users</value></property>      <br/>
 *   </bean>      <br/>
 * </p>
 * 
 * <h5>Active Directory Configuration</h5>
 * <p>
 * 	I haven't been able to test this directly, 
 *  but something like the following should do the trick:     <br/>
 *   <bean id="passwordAuthenticationDao"
 *       class="net.sf.acegisecurity.providers.dao.ldap.LdapPasswordAuthenticationDao">      <br/>
 *       <property name="url"><value>ldap://localhost:389/ou=system</value></property>      <br/>
 *       <property name="usernameFormat"><value>{0}@adDomainName</value></property>      <br/>
 *   </bean>      <br/>
 *   (if anyone gets this to work please let me know so I can include it 
 *   in the documentation).
 * </p>
 * 
 * 
 * @author Karel Miarka
 * @author Daniel Miller
 * @author Robert Sanders
 */
public class LdapPasswordAuthenticationDao extends InitialDirContextFactoryBean implements PasswordAuthenticationDao {

	private static final Log logger = LogFactory.getLog(LdapPasswordAuthenticationDao.class);

	public static final String BAD_CREDENTIALS_EXCEPTION_MESSAGE = "Invalid username, password or server configuration (JNDI Context).";
	
	/** Pattern used to turn the user's supplied username into the 
	 *  username format the LDAP server expects.  {0} is the username.
	 *  
	 *  <p>
	 *  Examples: <br/>
	 *  'Normal' LDAP: "cn={0}" <br/>
	 *  Active Directory style LDAP: "{0}@AD_Domain"
	 *  </p>
	 */
	private MessageFormat usernameFormat = new MessageFormat("cn={0}");
	
	/** Message format used to create the Name within the LDAP Context 
	 *  from which role information will be retrieved.
	 *  {0} is the username
	 *  {1} is the result of usernameFormat.format(new Object[] {username})
	 *  
	 *  <p>Example: "uid={0},ou=users"</p>
	 * 
	 */
	private MessageFormat userLookupNameFormat = null;

	/** List of LDAP Attributes which contian role name information. */
	private String[] roleAttributes = {"memberOf"};
	
	/** The role, which if non-null, will be grated the user if the user has no other roles. */
	private String defaultRole = null;
	
	public UserDetails loadUserByUsernameAndPassword(String username, String password) throws DataAccessException, BadCredentialsException {
		if ((password == null) || (password.length() == 0)) {
            throw new BadCredentialsException("Empty password");
        }
		
		String ldapUsername = (null == usernameFormat) ? username : usernameFormat.format( new Object[]{username} );
		if (logger.isDebugEnabled()) {
			logger.debug("Connecting to " + this.getUrl() + " as " + ldapUsername);
		}
		
	    InitialDirContext dirContext = null;
		try {
			dirContext = newInitialDirContext(ldapUsername, password);
		} catch (AuthenticationException ax) {
			throw new BadCredentialsException(BAD_CREDENTIALS_EXCEPTION_MESSAGE, ax);
		}
		if (null == dirContext) {
			throw new BadCredentialsException(BAD_CREDENTIALS_EXCEPTION_MESSAGE);
		}
		 
	    String[] roles = null;
	    if (null != roleAttributes) {
	    	try {
	    		String userContextName = (null == userLookupNameFormat) ? "" : 
	    			userLookupNameFormat.format(new Object[]{username, ldapUsername});
				roles = getRolesFromContext(dirContext, userContextName);
			} catch (NamingException e) {
				throw new DataAccessResourceFailureException("Unable to retrieve role information from LDAP Server.", e);
			}
	    }
	    if ((null == roles) && (null != defaultRole)) {
	    	roles = new String[] {defaultRole};
	    }
	    
	    return new User(username, password, true, true, true, true, toGrantedAuthority(roles) );
	}
	
	/** Converts from an Array of String rolenames to an array of GrantedAuthority objects.
	 *  This is a possible extension point for sub-classes to enrich the behavior of how 
	 *  the GrantedAuthority array is constucted.
	 *  
	 * @param rolenames Array of Strings representing the names of the 
	 * 		roles that the user has been granted according to the LDAP server.
	 * @return Array of GrantedAuthority objects which will be associated with the User's UserDetails.
	 */ 
	protected GrantedAuthority[] toGrantedAuthority(String[] rolenames) {
		if ((null == rolenames) || (rolenames.length == 0)) {
			return null;
		}
		
		GrantedAuthority[] grantedAuthorities = new GrantedAuthority[rolenames.length];
		for (int i = 0; i < rolenames.length; i++) {
	       grantedAuthorities[i] = toGrantedAuthority(rolenames[i]);
        }

	   return grantedAuthorities;
	}
	
	/** This is a possible extension point for sub-classes to enrich the behavior of how 
	 *  the GrantedAuthority object is constucted.
	 * 
	 * @param rolename Name of an LDAP role which is granted to the user.
	 * @return GrantedAuthority object which represents the granted role.
	 */
	protected GrantedAuthority toGrantedAuthority(String rolename) {
		GrantedAuthority ga = new GrantedAuthorityImpl( rolename );
		return ga;
	}
	
	/** 
	 * 
	 * @param ctx The LDAP DirContext retrieved by the user login.
	 * @return An array of roles granted the user found by searching all attributes named in the roleAttributes field.
	 * @throws NamingException 
	 */
	protected String[] getRolesFromContext(DirContext ctx, String dnOfUser) throws NamingException {
		if (null == roleAttributes) {
			return null;
		}
		
	    if (logger.isDebugEnabled()) {
	        String rolesString = "";

            for (int i = 0; i < roleAttributes.length; i++) {
                rolesString += (", " + roleAttributes[i]);
            }

            logger.debug("Searching ldap context for roles using attributes: " + rolesString.substring(1));
	    }
	    
	    ArrayList roles = new ArrayList();
	    Attributes attrs = null;
	    if (null == usernameFormat) {
	    	attrs = ctx.getAttributes("", roleAttributes);
	    } else {
	    	attrs = ctx.getAttributes(dnOfUser, roleAttributes);
	    }
	    
	    if (null != attrs) {
	    	NamingEnumeration attrsEnum = attrs.getAll();
	    	while ((attrsEnum != null) && (attrsEnum.hasMore())) {
	    		Attribute attr = (Attribute)attrsEnum.next();
	    		if (null != attr) {
		    		ArrayList list = getRolesFromAttribute( attr );
		    		if (null != list) {
		    			roles.addAll( list );
		    		}
	    		}
	    	}
	    }
	    
	    if (roles.isEmpty()) {
	    	return null;
	    } else {
	    	return (String[])roles.toArray( new String[roles.size()] );
	    }
	}
	
	protected ArrayList getRolesFromAttribute(Attribute attr) throws NamingException {
		NamingEnumeration rolesEnum = attr.getAll();
		if (null == rolesEnum) {
			return null;
		}
		
		ArrayList roles = new ArrayList();
		while (rolesEnum.hasMore()) {
			String rolename = (String)rolesEnum.next();
			if (null != rolename) {
				roles.add( convertLdapRolename(rolename) );
			}
		}
		return roles;
	}
	
	protected String convertLdapRolename(String name) {
		//System.out.println("Found LDAP UserRole = " + name);
		return name.toUpperCase();
	}

	public String getDefaultRole() {
		return defaultRole;
	}

	public void setDefaultRole(String defaultRole) {
		this.defaultRole = defaultRole;
	}

	public String[] getRoleAttributes() {
		return roleAttributes;
	}

	/** List of LDAP Attributes which contian role name information. */
	public void setRoleAttributes(String[] roleAttributes) {
		this.roleAttributes = roleAttributes;
	}
	
	/** Utility method to set a single attribute which contains role information.
	 *  @see setRoleAttributes
	 */
	public void setRoleAttribute(String roleAttribute) {
		setRoleAttributes(new String[]{ roleAttribute });
	}

	public String getUsernameFormat() {
		if (null == usernameFormat) {
			return null;
		} else {
			return usernameFormat.toPattern();
		}
	}
	
	/** Pattern used to turn the user's supplied username into the 
	 *  username format the LDAP server expects.
	 *  
	 *  <p>
	 *  Examples: <br/>
	 *  'Normal' LDAP: "cn={0}" <br/>
	 *  Active Directory style LDAP: "{0}@AD_Domain"
	 *  </p>
	 */
	public void setUsernameFormat(String usernameFormat) {
		if (null == usernameFormat) {
			this.usernameFormat = null;
		} else {
			this.usernameFormat = new MessageFormat(usernameFormat);
		}
	}
	

	public String getUserLookupNameFormat() {
		if (null == userLookupNameFormat) {
			return null;
		} else {
			return userLookupNameFormat.toPattern();
		}
	}

	public void setUserLookupNameFormat(String userLookupNameFormat) {
		if (null == userLookupNameFormat) {
			this.userLookupNameFormat = null;
		} else {
			this.userLookupNameFormat = new MessageFormat(userLookupNameFormat);
		}
	}
}
