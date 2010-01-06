package org.springframework.security.integration.multiannotation;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 *
 * @author Luke Taylor
 */
public interface PreAuthorizeService {

    @PreAuthorize("hasRole('ROLE_A')")
    void preAuthorizedMethod();
}
