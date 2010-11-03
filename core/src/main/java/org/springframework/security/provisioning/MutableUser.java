package org.springframework.security.provisioning;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 *
 * @author Luke Taylor
 * @since 3.1
 */
class MutableUser implements MutableUserDetails {
    private String password;
    private final UserDetails delegate;

    public MutableUser(UserDetails user) {
        this.delegate = user;
        this.password = user.getPassword();
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return delegate.getAuthorities();
    }

    public String getUsername() {
        return delegate.getUsername();
    }

    public boolean isAccountNonExpired() {
        return delegate.isAccountNonExpired();
    }

    public boolean isAccountNonLocked() {
        return delegate.isAccountNonLocked();
    }

    public boolean isCredentialsNonExpired() {
        return delegate.isCredentialsNonExpired();
    }

    public boolean isEnabled() {
        return delegate.isEnabled();
    }
}

