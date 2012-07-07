package org.springframework.security.acls.domain;

import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Creates the same SIDs as the SpringSecurity before the {@link SidFactory} was introduced, which means it creates a
 * {@link PrincipalSid} and {@link GrantedAuthoritySid}.
 *
 * @author stanislav bashkirtsev
 */
public class DefaultSidFactory implements SidFactory {
    /**
     * {@inheritDoc}
     */
    @Override
    public Sid create(String sidName, boolean principal) {
        if (principal) {
            return new PrincipalSid(sidName);
        } else {
            return new GrantedAuthoritySid(sidName);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Sid createPrincipal(Authentication authentication) {
        return new PrincipalSid(authentication);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<? extends Sid> createGrantedAuthorities(Collection<? extends GrantedAuthority> grantedAuthorities) {
        List<Sid> sids = new ArrayList<Sid>();
        for (GrantedAuthority authority : grantedAuthorities) {
            sids.add(new GrantedAuthoritySid(authority));
        }
        return sids;
    }
}
