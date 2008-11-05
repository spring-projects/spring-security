package org.springframework.security.acls.objectidentity;

import java.io.Serializable;

/**
 * Strategy which creates an <tt>ObjectIdentity</tt> from object identity and type information.
 * Used in situations when the actual object instance isn't available.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public interface ObjectIdentityGenerator {

    /**
     *
     * @param id the identifier of the domain object, not null
     * @param type the type of the object (usually a class name), not null
     * @return
     */
    ObjectIdentity createObjectIdentity(Serializable id, String type);

}
