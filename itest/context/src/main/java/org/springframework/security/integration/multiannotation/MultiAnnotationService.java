package org.springframework.security.integration.multiannotation;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Allows testing mixing of different annotation types
 *
 * @author Luke Taylor
 */
public interface MultiAnnotationService {

    @PreAuthorize("denyAll")
    void preAuthorizeDenyAllMethod();

    @PreAuthorize("hasRole('ROLE_A')")
    void preAuthorizeHasRoleAMethod();

    @Secured("IS_AUTHENTICATED_ANONYMOUSLY")
    void securedAnonymousMethod();

    @Secured("ROLE_A")
    void securedRoleAMethod();
}
