package org.springframework.security.openid;

import java.util.List;

/**
 * A strategy which can be used by an OpenID consumer implementation, to dynamically determine
 * the attribute exchange information based on the OpenID identifier.
 * <p>
 * This allows the list of attributes for a fetch request to be tailored for different OpenID providers, since they
 * do not all support the same attributes.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public interface AxFetchListFactory {

    /**
     * Builds the list of attributes which should be added to the fetch request for the
     * supplied OpenID identifier.
     *
     * @param identifier the claimed_identity
     * @return the attributes to fetch for this identifier
     */
    List<OpenIDAttribute> createAttributeList(String identifier);
}
