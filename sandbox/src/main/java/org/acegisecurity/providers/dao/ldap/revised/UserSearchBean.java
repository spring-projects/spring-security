/**
 * 
 */
package net.sf.acegisecurity.providers.dao.ldap.revised;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.springframework.beans.factory.InitializingBean;

/**
 * @author robert.sanders
 *
 */
public class UserSearchBean implements InitializingBean {

    /** Context relative to the rootContext to which the directory is connected. */
    private String subContext;
    
    /** If true then searches the entire subtree as idenified by context, 
     *  if false (the default) then only search the level identified by the context.
     */
    private boolean searchSubtree = false;
    
    /** The name and any associate information of the 
     *  ldap attribute used to match the username. 
     *  Expected in the form "uid={0}", or "uid={0}@company.com" 
     *  where {0} is the username that the user attempted to login with.
     */
    private String usernameFilter;
    
    /** LDAP Search Filter (@see 'RFC 2255').  NOTE: you can 
     *  use <b>either</b> searchFilter <b>or</b> filters, but <b>not</b> 
     *  both in a given LdapSearchBean.  
     */
    private String searchFilter = "objectClass=*";
    
    /** The attribute used when attempting to log the 
     *  user in to the LDAP server, if not set it defaults 
     *  to the attribute identified by usernameAttr.  
     *  For some LDAP systems this may need to be something like "sAMAccountName" (MS ActiveDirectory).
     */
    private String loginAttr;
    
    /** The time (in milliseconds) which to wait before the search fails; 
     *  the default is zero, meaning forever.
     */
    private int searchTimeLimit = 0;
    
    /** Attributes of the User's LDAP Object that contain role name information. */
    private String[] roleAttributes;
    
    /** Internal state - initialized at startup by combining the base searchFilter with the usernameFilter. */
    private String searchFilterInternal;
    
    /** Internal state - initialized at startup based on the values of the JavaBean properties. */
    private SearchControls searchControls;
    
    /** Return the JNDI SearchResult containing the user's information, or null if no SearchResult is found. 
     * 
     * @param ctx        The context in which the search will be based (note that subContext property refines this).
     * @param username   The username to search for.
     * @return           The JNDI SearchResult containing the user's information, or null if no SearchResult is found.
     * @throws NamingException  Passes on the Exception if a JNDI Exception occurs.
     */
    public UserSearchResults searchForUser(DirContext ctx, String username) throws NamingException {
        //System.out.println("searchFilterInternal [" + searchFilterInternal + "]");
        NamingEnumeration enm = ctx.search(subContext, searchFilterInternal, new String[]{username}, searchControls);
        if (!enm.hasMore()) {
            return null;    // user not found.
        }
        SearchResult searchResult = (SearchResult)enm.next();
        UserSearchResults userSearchResults = new UserSearchResults(searchResult);
        userSearchResults.setUserSearchBean(this);
        
        String userDN = searchResult.getName();
        if (searchResult.isRelative()) {
            userDN = userDN + "," +  subContext + "," + ctx.getNameInNamespace();
        }
        userSearchResults.setLdapName( userDN );
        
        String loginName;
        if (null != loginAttr) {
            loginName = (String)userSearchResults.getAttributes().get(loginAttr).get();
        } else {
            loginName = userDN;
        }
        userSearchResults.setUserLoginName(loginName);
        
        return userSearchResults;
    }

    public void afterPropertiesSet() throws Exception {
        searchControls = new SearchControls();
        if (searchSubtree) {
            searchControls.setSearchScope( SearchControls.SUBTREE_SCOPE );
        } else {
            searchControls.setSearchScope( SearchControls.ONELEVEL_SCOPE );
        }
        searchControls.setTimeLimit( searchTimeLimit );
        
        String baseFilter = (null != searchFilter) ? searchFilter : "";
        searchFilterInternal = "(&(" + baseFilter + ")(" + usernameFilter + "))";
    }

    /**
     * @return Returns the loginAttr.
     */
    public String getLoginAttr() {
        return loginAttr;
    }

    /**
     * @param loginAttr The loginAttr to set.
     */
    public void setLoginAttr(String loginAttr) {
        this.loginAttr = loginAttr;
    }

    /**
     * @return Returns the roleAttributes.
     */
    public String[] getRoleAttributes() {
        return roleAttributes;
    }

    /**
     * @param roleAttributes The roleAttributes to set.
     */
    public void setRoleAttributes(String[] roleAttributes) {
        this.roleAttributes = roleAttributes;
    }

    /**
     * @return Returns the searchFilter.
     */
    public String getSearchFilter() {
        return searchFilter;
    }

    /**
     * @param searchFilter The searchFilter to set.
     */
    public void setSearchFilter(String searchFilter) {
        this.searchFilter = searchFilter;
    }

    /**
     * @return Returns the searchSubtree.
     */
    public boolean isSearchSubtree() {
        return searchSubtree;
    }

    /**
     * @param searchSubtree The searchSubtree to set.
     */
    public void setSearchSubtree(boolean searchSubtree) {
        this.searchSubtree = searchSubtree;
    }

    /**
     * @return Returns the searchTimeLimit.
     */
    public int getSearchTimeLimit() {
        return searchTimeLimit;
    }

    /**
     * @param searchTimeLimit The searchTimeLimit to set.
     */
    public void setSearchTimeLimit(int searchTimeLimit) {
        this.searchTimeLimit = searchTimeLimit;
    }

    /**
     * @return Returns the subContext.
     */
    public String getSubContext() {
        return subContext;
    }

    /**
     * @param subContext The subContext to set.
     */
    public void setSubContext(String subContext) {
        this.subContext = subContext;
    }

    /**
     * @return Returns the usernameFilter.
     */
    public String getUsernameFilter() {
        return usernameFilter;
    }

    /**
     * @param usernameFilter The usernameFilter to set.
     */
    public void setUsernameFilter(String usernameFilter) {
        this.usernameFilter = usernameFilter;
    }
    
    
}
