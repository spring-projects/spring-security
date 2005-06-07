/**
 * 
 */
package net.sf.acegisecurity.providers.dao.ldap;

import java.util.ArrayList;
import java.util.Hashtable;

import javax.naming.Context;
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
import org.springframework.dao.DataAccessException;
import net.sf.acegisecurity.providers.dao.User;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.dao.PasswordAuthenticationDao;

/**
 * Re-written version of the ACEGI LDAP code, 
 *  designed to be cleaner; it is partially based on 
 *  the description of the mod_auth_ldap logic:  http://httpd.apache.org/docs-2.0/mod/mod_auth_ldap.html
 *  
 * 
 *
 */
public class LdapPassword2AuthenticationDao implements PasswordAuthenticationDao {

    public static final String BAD_CREDENTIALS_EXCEPTION_MESSAGE = "Invalid username, password or context";
    
    private static final transient Log logger = LogFactory.getLog(LdapPassword2AuthenticationDao.class);
    
    /** Ldap base settings. */
    private LdapSupport ldapSupport;
    
    /** Array of LdapSearchBean which will be used to search the context.
     */
    private UserSearchBean[] ldapSearchBeans;
    
    private String defaultRole;

    public UserDetails loadUserByUsernameAndPassword(String username, String password) throws DataAccessException, BadCredentialsException {
        if ((password == null) || (password.length() == 0)) {
            throw new BadCredentialsException("Empty password");
        }
        
        UserSearchResults userSearchResults = getUserBySearch(username);
        if (null == userSearchResults) {
            throw new BadCredentialsException(BAD_CREDENTIALS_EXCEPTION_MESSAGE);
        }
        
        DirContext userDirContext = null;
        try {
            userDirContext = loginToUserDirContext( userSearchResults.getUserLoginName(), password );
            if (null == userDirContext) {
                throw new BadCredentialsException(BAD_CREDENTIALS_EXCEPTION_MESSAGE);
            }
            
            String[] roleAttrs =  userSearchResults.getUserSearchBean().getRoleAttributes();
            GrantedAuthority[] roles = getUserRolesLdap(userDirContext, roleAttrs);

            if ((roles == null) && (null != defaultRole)) {
                roles = new GrantedAuthority[] { new GrantedAuthorityImpl(defaultRole) };
            }
            if (null != roles) {
                return new User( userSearchResults.getUserLoginName(), 
                    password, 
                    true,
                    true, 
                    true,
                    true, 
                    roles);
            } else {
                logger.info("User was able to login, but had no role information; username = [" + username + "]");
                throw new BadCredentialsException(BAD_CREDENTIALS_EXCEPTION_MESSAGE);
            }
        } finally {
            try {
                if (null != userDirContext) {
                    userDirContext.close();
                }
            } catch (NamingException e) {
                logger.warn("Unable to properly close userDirContext.", e);
            }
        }
    }
    
    protected UserSearchResults getUserBySearch(String username) throws DataAccessException, BadCredentialsException {
        InitialDirContext ctx = ldapSupport.getInitialContext();
        UserSearchResults userSearchResults = null;
        try {
            for (int i = 0; (i < ldapSearchBeans.length) && (null == userSearchResults); i++) {
                try {
                    userSearchResults = ldapSearchBeans[i].searchForUser(ctx, username);
                } catch (NamingException nx) {
                    logger.warn(nx);
                }
            }
        } finally {
            try {
                ctx.close();
            } catch (NamingException e) {
                logger.warn("Unable to properly close JNDI LDAP connection.", e);
            }
        }
        return userSearchResults;
    }
    
    
    protected DirContext loginToUserDirContext(String username, String password) {
        Hashtable baseEnv = ldapSupport.getEnvironment();
        baseEnv.put(Context.SECURITY_PRINCIPAL, username);
        baseEnv.put(Context.SECURITY_CREDENTIALS, password);
        try {
            return new InitialDirContext(baseEnv);
        } catch (NamingException e) {
            throw new BadCredentialsException(BAD_CREDENTIALS_EXCEPTION_MESSAGE, e);
        }
    }
    
    
    protected GrantedAuthority[] getUserRolesLdap(DirContext ctx, String[] roleAttrs) {
        try {
            NamingEnumeration enm = ctx.search((Name)null, null, roleAttrs, null);
            if (!enm.hasMore()) {
                return null;
            }
            
            // LDAP Search result which SHOULD contain the user's roles
            SearchResult searchResult = (SearchResult)enm.next();
            Attributes attrs = searchResult.getAttributes();
            
            
            ArrayList roleList = new ArrayList(attrs.size());
            NamingEnumeration attrEnm = attrs.getAll();
            while (attrEnm.hasMore()) {
                Attribute attr = (Attribute)attrEnm.next();
                for (int i = 0; i < attr.size(); i++) {
                    roleList.add( new GrantedAuthorityImpl((String)attr.get(i)) );
                }
            }
            
            GrantedAuthorityImpl[] roles = new GrantedAuthorityImpl[ roleList.size() ];
            return (GrantedAuthorityImpl[])roleList.toArray(roles);
        } catch (NamingException e) {
            // TODO Convert to authentication exception
            e.printStackTrace();
        } 
        return null;
    }

    /**
     * @return Returns the defaultRole.
     */
    public String getDefaultRole() {
        return defaultRole;
    }

    /**
     * @param defaultRole The defaultRole to set.
     */
    public void setDefaultRole(String defaultRole) {
        this.defaultRole = defaultRole;
    }
    
    
}
