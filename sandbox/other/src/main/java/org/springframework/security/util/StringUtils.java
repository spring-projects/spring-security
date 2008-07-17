/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.util;

import java.util.ArrayList;
import java.util.List;

/**
 * String manipulation methods.
 * 
 * @author Valery Tydykov
 * 
 */
public final class StringUtils {

    /**
     * This is a static class that should not be instantiated.
     */
    private StringUtils() throws InstantiationException {
    }

    /**
     * Tokenizes source string using another string as separator.
     * 
     * @param source source string
     * @param separator separator string
     * @return List of tokens found in the source string.
     */
    public static List tokenizeString(String source, String separator) {
        List tokens = new ArrayList();
        if (source != null && source.length() > 0) {
            while (source.indexOf(separator) != -1) {
                int index = source.indexOf(separator);
                tokens.add(source.substring(0, index));
                source = source.substring(index + separator.length());
            }
            tokens.add(source);
        }
        return tokens;
    }

    /**
     * Make sure a string is not null.
     * 
     * @param object string, might be null
     * @return empty string if the original was null or not String, else the original
     */
    public static String notNull(Object object) {
        if (object == null) {
            return "";
        } else if (!(object instanceof String)) {
            return String.valueOf(object);
        } else {
            return (String) object;
        }
    }
}
