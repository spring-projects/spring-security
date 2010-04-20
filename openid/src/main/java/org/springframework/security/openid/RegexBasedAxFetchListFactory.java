package org.springframework.security.openid;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 *
 * @author Luke Taylor
 * @since 3.1
 */
public class RegexBasedAxFetchListFactory implements AxFetchListFactory {
    private final Map<Pattern, List<OpenIDAttribute>> idToAttributes;

    /**
     * @param regexMap map of regular-expressions (matching the identifier) to attributes which should be fetched for
     * that pattern.
     */
    public RegexBasedAxFetchListFactory(Map<String, List<OpenIDAttribute>> regexMap) {
        idToAttributes = new LinkedHashMap<Pattern, List<OpenIDAttribute>>();
        for (Map.Entry<String, List<OpenIDAttribute>> entry : regexMap.entrySet()) {
            idToAttributes.put(Pattern.compile(entry.getKey()), entry.getValue());
        }
    }

    /**
     * Iterates through the patterns stored in the map and returns the list of attributes defined for the
     * first match. If no match is found, returns an empty list.
     */
    public List<OpenIDAttribute> createAttributeList(String identifier) {
        for (Map.Entry<Pattern, List<OpenIDAttribute>> entry : idToAttributes.entrySet()) {
            if (entry.getKey().matcher(identifier).matches()) {
                return entry.getValue();
            }
        }

        return Collections.emptyList();
    }

}
