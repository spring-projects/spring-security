/**
 * 
 */
package net.sf.acegisecurity.providers.dao.ldap;


import javax.naming.directory.SearchControls;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
/**
 * Used to specify properties which are used to 
 * construct JNDI SearchControls instances.
 * 
 * @see javax.naming.directory.SearchControls
 *
 */
public class SearchControlsFactory {
    
    private static final transient Log logger = LogFactory.getLog(SearchControlsFactory.class);

    /** Name, which when combined with the rootContext of the DirContext 
     *  being searched will resolve to the DN that the search should be performed in.
     */
    private String searchContextName;
    
    /** Names of the attributes to return from the search; 
     *  default is null in which case ALL attributes will be returned. 
     */
    private String[] returnAttrNames;
    
    /**
     * One of the 3 possible scope values as specified in SearchControles. <br/>
     * <ul>
     *   <li>SearchControls.OBJECT_SCOPE   = Search the attributes associated with the object specified by searchContextName.
     *   <li>SearchControls.ONELEVEL_SCOPE = Search the objects contained within the searchContextName.
     *   <li>SearchControls.SUBTREE_SCOPE = Recursivly search the objects contained within the searchContextName and any child context's it may contain.
     * </ul>
     * 
     */
    private int searchScope = SearchControls.ONELEVEL_SCOPE;

    /** Number of milliseconds to wait before a timeout error is triggered. */
    private int timeout = 10000;
    
    /** Maximum number of objects to return. Defauts to zero == no limit. */
    private int countLimit = 0;
    
    /** If set to true then links will be followed, 
     *  if left at the default of false then links will be returned (not followed).
     */
    private boolean followLinks = false;
    
    /** If set to true (the default) then objects can be returned from the LDAP server. */
    private boolean returnObjects = true;
    
    /** Given the settings for this LdapSearchCriteria, 
     *  use it to create a new instance of SearchControls with matching settings.
     * 
     * @return A new instance of SearchControls.
     */
    public SearchControls newSearchControls() {
        SearchControls controls = 
            new SearchControls(searchScope, countLimit, timeout, returnAttrNames, returnObjects, followLinks);        
        return controls;
    }

    /**
     * @return Returns the countLimit.
     */
    public int getCountLimit() {
        return countLimit;
    }

    /**
     * @param countLimit The countLimit to set.
     */
    public void setCountLimit(int countLimit) {
        this.countLimit = countLimit;
    }

    /**
     * @return Returns the followLinks.
     */
    public boolean isFollowLinks() {
        return followLinks;
    }

    /**
     * @param followLinks The followLinks to set.
     */
    public void setFollowLinks(boolean followLinks) {
        this.followLinks = followLinks;
    }

    /**
     * @return Returns the returnAttrNames.
     */
    public String[] getReturnAttrNames() {
        return returnAttrNames;
    }

    /**
     * @param returnAttrNames The returnAttrNames to set.
     */
    public void setReturnAttrNames(String[] returnAttrNames) {
        this.returnAttrNames = returnAttrNames;
    }

    /**
     * @return Returns the searchContextName.
     */
    public String getSearchContextName() {
        return searchContextName;
    }

    /**
     * @param searchContextName The searchContextName to set.
     */
    public void setSearchContextName(String searchContextName) {
        this.searchContextName = searchContextName;
    }

    /**
     * @return Returns the searchScope.
     */
    public int getSearchScope() {
        return searchScope;
    }

    /**
     * @param searchScope The searchScope to set.
     */
    public void setSearchScope(int searchScope) {
        this.searchScope = searchScope;
    }
    
    /** Set the searchScope using a string, should be one of: 
     *   OBJECT_SCOPE, ONELEVEL_SCOPE, or SUBTREE_SCOPE (you probably want ONELEVEL_SCOPE). 
     * 
     * @param scope
     */
    public void setSearchScope(String scope) {
        if ("OBJECT_SCOPE".equals(scope)) {
            setSearchScope( SearchControls.OBJECT_SCOPE );
        } else if ("ONELEVEL_SCOPE".equals(scope)) {
            setSearchScope( SearchControls.ONELEVEL_SCOPE );
        } else if ("SUBTREE_SCOPE".equals(scope)) {
            setSearchScope( SearchControls.SUBTREE_SCOPE );
        } else {
            logger.warn("Scope '" + scope + "' not recognized, setting to ONELEVEL_SCOPE");
            setSearchScope( SearchControls.ONELEVEL_SCOPE );
        }
    }

    /**
     * @return Returns the timeout.
     */
    public int getTimeout() {
        return timeout;
    }

    /**
     * @param timeout The timeout to set.
     */
    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }
    
    
}
