package org.springframework.security.samples.openid;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationToken;

/**
 * Custom UserDetailsService which accepts any OpenID user, "registering" new users in a map so they can be welcomed
 * back to the site on subsequent logins.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public class CustomUserDetailsService implements UserDetailsService, AuthenticationUserDetailsService<OpenIDAuthenticationToken> {

    private Map<String, CustomUserDetails> registeredUsers = new HashMap<String, CustomUserDetails>();

    private static final List<GrantedAuthority> DEFAULT_AUTHORITIES = AuthorityUtils.createAuthorityList("ROLE_USER");

    /**
     * Implementation of {@code UserDetailsService}. We only need this to satisfy the {@code RememberMeServices}
     * requirements.
     */
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        UserDetails user = registeredUsers.get(id);

        if (user == null) {
            throw new UsernameNotFoundException(id);
        }

        return user;
    }

    /**
     * Implementation of {@code AuthenticationUserDetailsService} which allows full access to the submitted
     * {@code Authentication} object. Used by the OpenIDAuthenticationProvider.
     */
    public UserDetails loadUserDetails(OpenIDAuthenticationToken token) {
        String id = token.getIdentityUrl();

        CustomUserDetails user = registeredUsers.get(id);

        if (user != null) {
            return user;
        }

        String email = null;
        String firstName = null;
        String lastName = null;
        String fullName = null;

        List<OpenIDAttribute> attributes = token.getAttributes();

        for (OpenIDAttribute attribute : attributes) {
            if (attribute.getName().equals("email")) {
                email = attribute.getValues().get(0);
            }

            if (attribute.getName().equals("firstname")) {
                firstName = attribute.getValues().get(0);
            }

            if (attribute.getName().equals("fullname")) {
                fullName = attribute.getValues().get(0);
            }
        }

        if (fullName == null) {
            StringBuilder fullNameBldr = new StringBuilder();

            if (firstName != null) {
                fullNameBldr.append(firstName);
            }

            if (lastName != null) {
                fullNameBldr.append(" ").append(lastName);
            }
            fullName = fullNameBldr.toString();
        }

        user = new CustomUserDetails(id, DEFAULT_AUTHORITIES);
        user.setEmail(email);
        user.setName(fullName);

        registeredUsers.put(id, user);

        user = new CustomUserDetails(id, DEFAULT_AUTHORITIES);
        user.setEmail(email);
        user.setName(fullName);
        user.setNewUser(true);

        return user;
    }
}
