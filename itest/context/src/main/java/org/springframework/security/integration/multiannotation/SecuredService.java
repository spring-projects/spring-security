package org.springframework.security.integration.multiannotation;

import org.springframework.security.access.annotation.Secured;

/**
 *
 * @author Luke Taylor
 */
public interface SecuredService {
    @Secured("ROLE_A")
    void securedMethod();
}
