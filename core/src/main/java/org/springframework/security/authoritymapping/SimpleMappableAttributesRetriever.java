package org.springframework.security.authoritymapping;

import java.util.Arrays;
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
     * @see org.springframework.security.authoritymapping.MappableAttributesRetriever#getMappableAttributes()
     */
    public Set<String> getMappableAttributes() {
        return mappableAttributes;
    }

    public void setMappableAttributes(String[] aMappableRoles) {
        mappableAttributes = new HashSet<String>(aMappableRoles.length);
        mappableAttributes.addAll(Arrays.asList(aMappableRoles));
        mappableAttributes = Collections.unmodifiableSet(mappableAttributes);
    }

}
