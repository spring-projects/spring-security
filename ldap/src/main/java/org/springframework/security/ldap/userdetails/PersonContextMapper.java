package org.springframework.security.ldap.userdetails;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.util.Assert;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class PersonContextMapper implements UserDetailsContextMapper {

    public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<GrantedAuthority> authorities) {
        Person.Essence p = new Person.Essence(ctx);

        p.setUsername(username);
        p.setAuthorities(authorities);

        return p.createUserDetails();

    }

    public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
        Assert.isInstanceOf(Person.class, user, "UserDetails must be a Person instance");

        Person p = (Person) user;
        p.populateContext(ctx);
    }
}
