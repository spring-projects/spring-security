package org.acegisecurity.userdetails.ldap;

import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.GrantedAuthority;
import org.springframework.ldap.support.DirContextOperations;
import org.springframework.ldap.support.DirContextAdapter;
import org.springframework.util.Assert;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class PersonContextMapper implements UserDetailsContextMapper {

    public UserDetails mapUserFromContext(DirContextOperations ctx, String username, GrantedAuthority[] authorities) {
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
