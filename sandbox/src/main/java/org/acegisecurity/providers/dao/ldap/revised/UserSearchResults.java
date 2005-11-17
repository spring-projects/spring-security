/**
 * 
 */
package org.acegisecurity.providers.dao.ldap.revised;

import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/**
 * Encapsulates the information returned by a successful UserSearchBean
 *
 */
public class UserSearchResults {
    
    private Attributes attributes;
    
    /** The full DN of the user. */
    private String ldapName;
    
    /** The name that should be used to log the user into the LDAP server (to test authentication). */
    private String userLoginName;
    
    /** Internal state: the UserSearchBean which yeilded the results. */
    private UserSearchBean userSearchBean;
    
    public UserSearchResults() {
        super();
    }
    
    public UserSearchResults(SearchResult searchResult) {
        super();
        setAttributes( searchResult.getAttributes() );
    }
    
    public UserSearchResults(SearchResult searchResult, UserSearchBean userSearchBean) {
        super();
        this.userSearchBean = userSearchBean;
        setAttributes( searchResult.getAttributes() );
    }
    
    /**
     * @return Returns the attributes.
     */
    public Attributes getAttributes() {
        return attributes;
    }

    /**
     * @param attributes The attributes to set.
     */
    public void setAttributes(Attributes attributes) {
        this.attributes = attributes;
    }

    /**
     * @return Returns the name.
     */
    public String getLdapName() {
        return ldapName;
    }

    /**
     * @param name The name to set.
     */
    public void setLdapName(String name) {
        this.ldapName = name;
    }

    /**
     * @return Returns the userLoginName.
     */
    public String getUserLoginName() {
        return userLoginName;
    }

    /**
     * @param userLoginName The userLoginName to set.
     */
    public void setUserLoginName(String userLoginName) {
        this.userLoginName = userLoginName;
    }

    /**
     * @return Returns the userSearchBean.
     */
    public UserSearchBean getUserSearchBean() {
        return userSearchBean;
    }

    /**
     * @param userSearchBean The userSearchBean to set.
     */
    public void setUserSearchBean(UserSearchBean userSearchBean) {
        this.userSearchBean = userSearchBean;
    }
    
}
