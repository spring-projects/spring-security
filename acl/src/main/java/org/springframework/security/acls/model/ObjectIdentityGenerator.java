package org.springframework.security.acls.model;

import java.io.Serializable;


/**
 * Strategy which creates an {@link ObjectIdentity} from an object identifier (such as a primary key)
 * and type information.
 * <p>
 * Differs from {@link ObjectIdentityRetrievalStrategy} in that it is used in situations when the actual object
 * instance isn't available.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface ObjectIdentityGenerator {

    /**
     *
     * @param id the identifier of the domain object, not null
     * @param type the type of the object (often a class name), not null
     * @return the identity constructed using the supplied identifier and type information.
     */
    ObjectIdentity createObjectIdentity(Serializable id, String type);

}
