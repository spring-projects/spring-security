package org.springframework.security.access.authoritymapping;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * This class implements the MappableAttributesRetriever interface by just returning
 * a list of mappable attributes as previously set using the corresponding setter
 * method.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class SimpleMappableAttributesRetriever implements MappableAttributesRetriever {
    private Set<String> mappableAttributes = null;

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.security.access.authoritymapping.MappableAttributesRetriever#getMappableAttributes()
     */
    public Set<String> getMappableAttributes() {
        return mappableAttributes;
    }

    @SuppressWarnings("unchecked")
    public void setMappableAttributes(Set aMappableRoles) {
        mappableAttributes = new HashSet<String>();
        mappableAttributes.addAll(aMappableRoles);
        mappableAttributes = Collections.unmodifiableSet(mappableAttributes);
    }

}
