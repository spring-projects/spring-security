package org.springframework.security.acls.domain;

import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

/**
 * Typical application that uses Spring ACL won't need anything but {@link PrincipalSid} or {@link GrantedAuthoritySid},
 * but sometimes we need to extend this list of implementations or replace it for more complicated scenarios when
 * default capabilities of Spring ACL is not enough. You can implement this factory and inject it into different classes
 * that work with {@link Sid}s in order them to create <i>your</i> SIDs.
 *
 * @author stanislav bashkirtsev
 */
public interface SidFactory {
    /**
     * The Factory Method that creates a particular implementation of {@link Sid} depending on the arguments.
     *
     * @param sidName   the name of the sid representing its unique identifier. In typical ACL database schema it's
     *                  located in table {@code acl_sid} table, {@code sid} column.
     * @param principal whether it's a user or granted authority like role
     * @return the instance of Sid with the {@code sidName} as an identifier
     */
    Sid create(String sidName, boolean principal);

    /**
     * Creates a principal-like sid from the authentication information.
     *
     * @param authentication the authentication information that can provide principal and thus the sid's id will be
     *                       dependant on the value inside
     * @return a sid with the ID taken from the authentication information
     */
    Sid createPrincipal(Authentication authentication);

    List<? extends Sid> createGrantedAuthorities(Collection<? extends GrantedAuthority> grantedAuthorities);
}
