/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.userdetails.ldap;

import org.acegisecurity.GrantedAuthority;

import org.springframework.util.Assert;
import org.springframework.ldap.support.DirContextOperations;
import org.springframework.ldap.support.DirContextAdapter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Iterator;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.ldap.Control;


/**
 * A UserDetails implementation which is used internally by the Ldap services. It also contains the user's
 * distinguished name and a set of attributes that have been retrieved from the Ldap server.
 * <p>
 * An instance may be created as the result of a search, or when user information is retrieved during authentication.
 * </p>
 * <p>
 * An instance of this class will be used by the <tt>LdapAuthenticationProvider</tt> to construct the final user details
 * object that it returns.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsImpl implements LdapUserDetails {
    //~ Static fields/initializers =====================================================================================

    private static final GrantedAuthority[] NO_AUTHORITIES = new GrantedAuthority[0];
    private static final Control[] NO_CONTROLS = new Control[0];

    //~ Instance fields ================================================================================================

    private Attributes attributes = new BasicAttributes();
    private String dn;
    private String password;
    private String username;
    private GrantedAuthority[] authorities = NO_AUTHORITIES;
    private Control[] controls = NO_CONTROLS;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;

    //~ Constructors ===================================================================================================

    protected LdapUserDetailsImpl() {}

    //~ Methods ========================================================================================================

    public Attributes getAttributes() {
        return attributes;
    }

    public GrantedAuthority[] getAuthorities() {
        return authorities;
    }

    public Control[] getControls() {
        return controls;
    }

    public String getDn() {
        return dn;
    }

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }

    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public boolean isEnabled() {
        return enabled;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Variation of essence pattern. Used to create mutable intermediate object
     */
    public static class Essence {
        protected LdapUserDetailsImpl instance = createTarget();
        private List mutableAuthorities = new ArrayList();

        public Essence() { }

        public Essence(DirContextOperations ctx) {
            setDn(ctx.getDn().toString());
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

        protected LdapUserDetailsImpl createTarget() {
            return new LdapUserDetailsImpl();
        }

        /** Adds the authority to the list, unless it is already there, in which case it is ignored */
        public void addAuthority(GrantedAuthority a) {
            if(!hasAuthority(a)) {
                mutableAuthorities.add(a);
            }
        }

        private boolean hasAuthority(GrantedAuthority a) {
            Iterator authorities = mutableAuthorities.iterator();

            while(authorities.hasNext()) {
                GrantedAuthority authority = (GrantedAuthority) authorities.next();
                if(authority.equals(a)) {
                    return true;
                }
            }
            return false;
        }

        public LdapUserDetails createUserDetails() {
            //TODO: Validation of properties
            Assert.notNull(instance, "Essence can only be used to create a single instance");

            instance.authorities = getGrantedAuthorities();

            LdapUserDetails newInstance = instance;

            instance = null;

            return newInstance;
        }

        public GrantedAuthority[] getGrantedAuthorities() {
            return (GrantedAuthority[]) mutableAuthorities.toArray(new GrantedAuthority[0]);
        }

        public void setAccountNonExpired(boolean accountNonExpired) {
            instance.accountNonExpired = accountNonExpired;
        }

        public void setAccountNonLocked(boolean accountNonLocked) {
            instance.accountNonLocked = accountNonLocked;
        }

        public void setAttributes(Attributes attributes) {
            instance.attributes = attributes;
        }

        public void setAuthorities(GrantedAuthority[] authorities) {
            mutableAuthorities = new ArrayList(Arrays.asList(authorities));
        }

        public void setControls(Control[] controls) {
            instance.controls = controls;
        }

        public void setCredentialsNonExpired(boolean credentialsNonExpired) {
            instance.credentialsNonExpired = credentialsNonExpired;
        }

        public void setDn(String dn) {
            instance.dn = dn;
        }

        public void setEnabled(boolean enabled) {
            instance.enabled = enabled;
        }

        public void setPassword(String password) {
            instance.password = password;
        }

        public void setUsername(String username) {
            instance.username = username;
        }
    }
}
