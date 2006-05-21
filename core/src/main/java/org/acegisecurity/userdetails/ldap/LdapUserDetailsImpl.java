package org.acegisecurity.userdetails.ldap;

import org.acegisecurity.GrantedAuthority;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.ldap.Control;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * A UserDetails implementation which is used internally by the Ldap services.
 *
 * It also contains the user's distinguished name and a set of attributes that
 * have been retrieved from the Ldap server.
 * <p>
 * An instance may be created as the result of a search, or when user information
 * is retrieved during authentication.
 * </p>
 * <p>
 * An instance of this class will be used by the <tt>LdapAuthenticationProvider</tt>
 * to construct the final user details object that it returns.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsImpl implements LdapUserDetails {

    private static final GrantedAuthority[] NO_AUTHORITIES = new GrantedAuthority[0];
    private static final Control[] NO_CONTROLS = new Control[0];

    //~ Instance fields ========================================================

    private String dn;
    private Attributes attributes = new BasicAttributes();
    private String username;
    private String password;
    private boolean enabled = true;
    private boolean accountNonExpired = true;
    private boolean credentialsNonExpired = true;
    private boolean accountNonLocked = true;
    private GrantedAuthority[] authorities = NO_AUTHORITIES;
    private Control[] controls = NO_CONTROLS;

    //~ Constructors ===========================================================

    protected LdapUserDetailsImpl() {
    }

    //~ Methods ================================================================

    public String getDn() {
        return dn;
    }

    public Attributes getAttributes() {
        return attributes;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public GrantedAuthority[] getAuthorities() {
        return authorities;
    }

    public Control[] getControls() {
        return controls;
    }

    //~ Inner classes ==========================================================

    /** Variation of essence pattern. Used to create mutable intermediate object */
    public static class Essence {

        LdapUserDetailsImpl instance = new LdapUserDetailsImpl();

        List mutableAuthorities = new ArrayList();

        public Essence() {
        }

        public Essence(LdapUserDetails copyMe) {
            setDn(copyMe.getDn());
            setAttributes(copyMe.getAttributes());
            setUsername(copyMe.getUsername());
            setPassword(copyMe.getPassword());
            setEnabled(copyMe.isEnabled());
            setAccountNonExpired(copyMe.isAccountNonExpired());
            setCredentialsNonExpired(copyMe.isCredentialsNonExpired());
            setAccountNonLocked(copyMe.isAccountNonLocked());
            setControls(copyMe.getControls());
            setAuthorities(copyMe.getAuthorities());
        }

        public Essence setDn(String dn) {
            instance.dn = dn;
            return this;
        }

        public Essence setAttributes(Attributes attributes) {
            instance.attributes = attributes;
            return this;
        }

        public Essence setUsername(String username) {
            instance.username = username;
            return this;
        }

        public Essence setPassword(String password) {
            instance.password = password;
            return this;
        }

        public Essence setEnabled(boolean enabled) {
            instance.enabled = enabled;
            return this;
        }

        public Essence setAccountNonExpired(boolean accountNonExpired) {
            instance.accountNonExpired = accountNonExpired;
            return this;
        }

        public Essence setCredentialsNonExpired(boolean credentialsNonExpired) {
            instance.credentialsNonExpired = credentialsNonExpired;
            return this;
        }

        public Essence setAccountNonLocked(boolean accountNonLocked) {
            instance.accountNonLocked = accountNonLocked;
            return this;
        }

        public Essence setAuthorities(GrantedAuthority[] authorities) {
            mutableAuthorities = new ArrayList(Arrays.asList(authorities));
            return this;
        }

        public Essence addAuthority(GrantedAuthority a) {
            mutableAuthorities.add(a);

            return this;
        }

        public GrantedAuthority[] getGrantedAuthorities() {
            return (GrantedAuthority[])mutableAuthorities.toArray(new GrantedAuthority[0]);
        }

        public void setControls(Control[] controls) {
            instance.controls = controls;
        }

        public LdapUserDetails createUserDetails() {
            //TODO: Validation of properties

            instance.authorities = getGrantedAuthorities();

            return instance;
        }
    }
}
