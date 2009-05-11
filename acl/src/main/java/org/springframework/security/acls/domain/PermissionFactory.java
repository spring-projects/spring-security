package org.springframework.security.acls.domain;

import org.springframework.security.acls.model.Permission;

/**
 * Provides a simple mechanism to retrieve {@link Permission} instances from integer masks.
 * 
 * @author Ben Alex
 * @since 2.0.3
 * 
 */
public interface PermissionFactory {

    /**
     * Dynamically creates a <code>CumulativePermission</code> or <code>BasePermission</code> representing the
     * active bits in the passed mask.
     *
     * @param mask to build
     *
     * @return a Permission representing the requested object
     */
    public abstract Permission buildFromMask(int mask);

}