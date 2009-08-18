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

package org.springframework.security.ldap.userdetails;

import java.util.ArrayList;
import java.util.List;

import javax.naming.Name;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.ldap.ppolicy.PasswordPolicyData;
import org.springframework.util.Assert;


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
public class LdapUserDetailsImpl implements LdapUserDetails, PasswordPolicyData {

    //~ Instance fields ================================================================================================

    private String dn;
    private String password;
    private String username;
    private List<GrantedAuthority> authorities = AuthorityUtils.NO_AUTHORITIES;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;
    // PPolicy data
    private int timeBeforeExpiration = Integer.MAX_VALUE;
    private int graceLoginsRemaining = Integer.MAX_VALUE;

    //~ Constructors ===================================================================================================

    protected LdapUserDetailsImpl() {}

    //~ Methods ========================================================================================================

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
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

    public int getTimeBeforeExpiration() {
        return timeBeforeExpiration;
    }

    public int getGraceLoginsRemaining() {
        return graceLoginsRemaining;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString()).append(": ");
        sb.append("Username: ").append(this.username).append("; ");
        sb.append("Password: [PROTECTED]; ");
        sb.append("Enabled: ").append(this.enabled).append("; ");
        sb.append("AccountNonExpired: ").append(this.accountNonExpired).append("; ");
        sb.append("credentialsNonExpired: ").append(this.credentialsNonExpired).append("; ");
        sb.append("AccountNonLocked: ").append(this.accountNonLocked).append("; ");

        if (this.getAuthorities() != null) {
            sb.append("Granted Authorities: ");

            for (int i = 0; i < this.getAuthorities().size(); i++) {
                if (i > 0) {
                    sb.append(", ");
                }

                sb.append(this.getAuthorities().get(i).toString());
            }
        } else {
            sb.append("Not granted any authorities");
        }

        return sb.toString();
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Variation of essence pattern. Used to create mutable intermediate object
     */
    public static class Essence {
        protected LdapUserDetailsImpl instance = createTarget();
        private List<GrantedAuthority> mutableAuthorities = new ArrayList<GrantedAuthority>();

        public Essence() { }

        public Essence(DirContextOperations ctx) {
            setDn(ctx.getDn());
        }

        public Essence(LdapUserDetails copyMe) {
            setDn(copyMe.getDn());
            setUsername(copyMe.getUsername());
            setPassword(copyMe.getPassword());
            setEnabled(copyMe.isEnabled());
            setAccountNonExpired(copyMe.isAccountNonExpired());
            setCredentialsNonExpired(copyMe.isCredentialsNonExpired());
            setAccountNonLocked(copyMe.isAccountNonLocked());
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
            for (GrantedAuthority authority : mutableAuthorities) {
                if(authority.equals(a)) {
                    return true;
                }
            }
            return false;
        }

        public LdapUserDetails createUserDetails() {
            Assert.notNull(instance, "Essence can only be used to create a single instance");
            Assert.notNull(instance.username, "username must not be null");
            Assert.notNull(instance.getDn(), "Distinguished name must not be null");

            instance.authorities = getGrantedAuthorities();

            LdapUserDetails newInstance = instance;

            instance = null;

            return newInstance;
        }

        public List<GrantedAuthority> getGrantedAuthorities() {
            return mutableAuthorities;
        }

        public void setAccountNonExpired(boolean accountNonExpired) {
            instance.accountNonExpired = accountNonExpired;
        }

        public void setAccountNonLocked(boolean accountNonLocked) {
            instance.accountNonLocked = accountNonLocked;
        }

        public void setAuthorities(List<GrantedAuthority> authorities) {
            mutableAuthorities = authorities;
        }

        public void setCredentialsNonExpired(boolean credentialsNonExpired) {
            instance.credentialsNonExpired = credentialsNonExpired;
        }

        public void setDn(String dn) {
            instance.dn = dn;
        }

        public void setDn(Name dn) {
            instance.dn = dn.toString();
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

        public void setTimeBeforeExpiration(int timeBeforeExpiration) {
            instance.timeBeforeExpiration = timeBeforeExpiration;
        }

        public void setGraceLoginsRemaining(int graceLoginsRemaining) {
            instance.graceLoginsRemaining = graceLoginsRemaining;
        }
    }
}
