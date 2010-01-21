package org.springframework.security.acls.model;

import java.util.List;

/**
 * Allow customization of the logic for determining whether a permission or permissions are granted to a particular
 * sid or sids by an {@link Acl}.
 *
 * @author Luke Taylor
 * @since 3.0.2
 */
public interface PermissionGrantingStrategy {

    /**
     * Returns true if the the supplied strategy decides that the supplied {@code Acl} grants access
     * based on the supplied list of permissions and sids.
     */
    boolean isGranted(Acl acl, List<Permission> permission, List<Sid> sids, boolean administrativeMode);

}
