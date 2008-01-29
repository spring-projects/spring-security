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

package org.springframework.security.intercept.web;

import java.beans.PropertyEditorSupport;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.util.StringSplitUtils;
import org.springframework.security.util.RegexUrlPathMatcher;
import org.springframework.security.util.UrlMatcher;
import org.springframework.security.util.AntUrlPathMatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.StringUtils;


/**
 * Property editor to assist with the setup of a {@link FilterInvocationDefinitionSource}.
 * <p>
 * Note that from version 2.0, the use of property-editor based configuration is deprecated in favour of namespace
 * configuration options.
 * <p>
 * The class creates and populates a
 * {@link org.springframework.security.intercept.web.DefaultFilterInvocationDefinitionSource}
 * using either an Ant or Regular Expression URL matching strategy depending on the type of patterns presented.
 * <p>
 * By default the class treats presented patterns as regular expressions. If the keyword
 * <code>PATTERN_TYPE_APACHE_ANT</code> is present (case sensitive), patterns will be treated as Apache Ant paths
 * rather than regular expressions.
 *
 * @author Ben Alex
 * @deprecated Use namespace configuration instead. May be removed in future versions.
 * @version $Id$
 */
public class FilterInvocationDefinitionSourceEditor extends PropertyEditorSupport {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(FilterInvocationDefinitionSourceEditor.class);
    public static final String DIRECTIVE_CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON =
            "CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON";
    public static final String DIRECTIVE_PATTERN_TYPE_APACHE_ANT = "PATTERN_TYPE_APACHE_ANT";

    //~ Methods ========================================================================================================

    public void setAsText(String s) throws IllegalArgumentException {
        if ((s == null) || "".equals(s)) {
            // Leave target object empty
            setValue(new DefaultFilterInvocationDefinitionSource(new RegexUrlPathMatcher()));

            return;
        }

        boolean useAnt = s.lastIndexOf(DIRECTIVE_PATTERN_TYPE_APACHE_ANT) != -1;
        boolean converUrlToLowerCase = s.lastIndexOf(DIRECTIVE_CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON) != -1;

        if (logger.isDebugEnabled()) {
            if (useAnt) {
                logger.debug(("Detected " + DIRECTIVE_PATTERN_TYPE_APACHE_ANT
                    + " directive; using Apache Ant style path expressions"));
            }

            if (converUrlToLowerCase) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Detected " + DIRECTIVE_CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON
                        + " directive; Instructing mapper to convert URLs to lowercase before comparison");
                }
            }
        }

        UrlMatcher matcher;

        if (useAnt) {
            matcher = new AntUrlPathMatcher();
            ((AntUrlPathMatcher)matcher).setRequiresLowerCaseUrl(converUrlToLowerCase);

        } else {
            matcher = new RegexUrlPathMatcher();
            ((RegexUrlPathMatcher)matcher).setRequiresLowerCaseUrl(converUrlToLowerCase);
        }

        DefaultFilterInvocationDefinitionSource fids = new DefaultFilterInvocationDefinitionSource(matcher);

        if (useAnt) {
            fids.setStripQueryStringFromUrls(true);
        }


        BufferedReader br = new BufferedReader(new StringReader(s));
        int counter = 0;
        String line;

        List mappings = new ArrayList();

        while (true) {
            counter++;

            try {
                line = br.readLine();
            } catch (IOException ioe) {
                throw new IllegalArgumentException(ioe.getMessage());
            }

            if (line == null) {
                break;
            }

            line = line.trim();

            if (logger.isDebugEnabled()) {
                logger.debug("Line " + counter + ": " + line);
            }

            if (line.startsWith("//")) {
                continue;
            }

            // Attempt to detect malformed lines (as per SEC-204)
            if (line.lastIndexOf(DIRECTIVE_CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON) != -1) {
                // Directive found; check for second directive or name=value
                if ((line.lastIndexOf(DIRECTIVE_PATTERN_TYPE_APACHE_ANT) != -1) || (line.lastIndexOf("=") != -1)) {
                    throw new IllegalArgumentException("Line appears to be malformed: " + line);
                }
            }

            // Attempt to detect malformed lines (as per SEC-204)
            if (line.lastIndexOf(DIRECTIVE_PATTERN_TYPE_APACHE_ANT) != -1) {
                // Directive found; check for second directive or name=value
                if ((line.lastIndexOf(DIRECTIVE_CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON) != -1)
                    || (line.lastIndexOf("=") != -1)) {
                    throw new IllegalArgumentException("Line appears to be malformed: " + line);
                }
            }

            // Skip lines that are not directives
            if (line.lastIndexOf('=') == -1) {
                continue;
            }

            if (line.lastIndexOf("==") != -1) {
                throw new IllegalArgumentException("Only single equals should be used in line " + line);
            }

            // Tokenize the line into its name/value tokens
            // As per SEC-219, use the LAST equals as the delimiter between LHS and RHS
            String name = StringSplitUtils.substringBeforeLast(line, "=");
            String value = StringSplitUtils.substringAfterLast(line, "=");

            if (!StringUtils.hasText(name) || !StringUtils.hasText(value)) {
                throw new IllegalArgumentException("Failed to parse a valid name/value pair from " + line);
            }

            // Attempt to detect malformed lines (as per SEC-204)
            if (converUrlToLowerCase && useAnt) {
                // Should all be lowercase; check each character
                // We only do this for Ant (regexp have control chars)
                for (int i = 0; i < name.length(); i++) {
                    String character = name.substring(i, i + 1);

                    if (!character.toLowerCase().equals(character)) {
                        throw new IllegalArgumentException("You are using the "
                            + DIRECTIVE_CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON
                            + " with Ant Paths, yet you have specified an uppercase character in line: " + line
                            + " (character '" + character + "')");
                    }
                }
            }

            FilterInvocationDefinitionSourceMapping mapping = new FilterInvocationDefinitionSourceMapping();
            mapping.setUrl(name);

            String[] tokens = StringUtils.commaDelimitedListToStringArray(value);

            for (int i = 0; i < tokens.length; i++) {
                mapping.addConfigAttribute(tokens[i].trim());
            }

            mappings.add(mapping);
        }
        fids.setMappings(mappings);

        setValue(fids);
    }
}
