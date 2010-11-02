package org.springframework.security.core.authority;

import java.util.*;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

@Deprecated
public class GrantedAuthoritiesContainerImpl implements MutableGrantedAuthoritiesContainer {
    private List<GrantedAuthority> authorities;

    public void setGrantedAuthorities(Collection<? extends GrantedAuthority> newAuthorities) {
        ArrayList<GrantedAuthority> temp = new ArrayList<GrantedAuthority>(newAuthorities.size());
        temp.addAll(newAuthorities);
        authorities = Collections.unmodifiableList(temp);
    }

    public List<GrantedAuthority> getGrantedAuthorities() {
        Assert.notNull(authorities, "Granted authorities have not been set");
        return authorities;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Authorities: ").append(authorities);
        return sb.toString();
    }
}
