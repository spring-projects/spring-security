package net.sf.acegisecurity.providers.jaas;

import java.security.Principal;

/**
 * The AuthorityGranter interface is used to map a given principal to a role name.
 * If a Windows NT login module were to be used from JAAS, an AuthrityGranter implementation could be created
 * to map a NT Group Principal to a ROLE_USER role for instance.
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public interface AuthorityGranter {

    /**
     * The grant method is called for each principal returned from the LoginContext subject.
     * If the AuthorityGranter wishes to grant authority, it should return the role name, such as ROLE_USER.
     * If the AuthrityGranter does not wish to grant any authority it should return null.
     *
     * @param principal One of the principal from the LoginContext.getSubect().getPrincipals() method.
     * @return The name of a role to grant, or null meaning no role should be granted.
     */
    public String grant(Principal principal);
}
