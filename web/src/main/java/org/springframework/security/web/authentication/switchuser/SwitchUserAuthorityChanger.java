package org.springframework.security.web.authentication.switchuser;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Allows subclasses to modify the {@link GrantedAuthority} list that will be assigned to the principal
 * when they assume the identity of a different principal.
 *
 * <p>Configured against the {@link SwitchUserFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 *
 */
public interface SwitchUserAuthorityChanger {

    /**
     * Allow subclasses to add or remove authorities that will be granted when in switch user mode.
     *
     * @param targetUser the UserDetails representing the identity being switched to
     * @param currentAuthentication the current Authentication of the principal performing the switching
     * @param authoritiesToBeGranted all {@link GrantedAuthority} instances to be granted to the user,
     * excluding the special "switch user" authority that is used internally (guaranteed never null)
     *
     * @return the modified list of granted authorities.
     */
    Collection<GrantedAuthority> modifyGrantedAuthorities(UserDetails targetUser, Authentication currentAuthentication, Collection<GrantedAuthority> authoritiesToBeGranted);
}
