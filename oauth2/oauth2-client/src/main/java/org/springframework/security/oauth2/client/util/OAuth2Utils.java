package org.springframework.security.oauth2.client.util;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

/**
 * Created by XYUU on 2018/4/24.
 */
public class OAuth2Utils {

    /**
     * Parses a string parameter value into a set of strings.
     *
     * @param values The values of the set.
     * @return The set.
     */
    public static Set<String> parseParameterList(String values) {
        Set<String> result = new TreeSet<String>();
        if (values != null && values.trim().length() > 0) {
            // the spec says the scope is separated by spaces
            String[] tokens = values.split("[\\s+]");
            result.addAll(Arrays.asList(tokens));
        }
        return result;
    }
}
