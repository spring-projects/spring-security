/* Copyright 2004 Acegi Technology Pty Limited
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

package org.acegisecurity.intercept.web;

import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.ConfigAttributeEditor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.StringUtils;

import java.beans.PropertyEditorSupport;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;


/**
 * Property editor to assist with the setup of a {@link
 * FilterInvocationDefinitionSource}.
 * 
 * <p>
 * The class creates and populates a {@link
 * RegExpBasedFilterInvocationDefinitionMap} or {@link
 * PathBasedFilterInvocationDefinitionMap} (depending on the type of patterns
 * presented).
 * </p>
 * 
 * <p>
 * By default the class treats presented patterns as regular expressions. If
 * the keyword <code>PATTERN_TYPE_APACHE_ANT</code> is present (case
 * sensitive), patterns will be treated as Apache Ant paths rather than
 * regular expressions.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class FilterInvocationDefinitionSourceEditor
    extends PropertyEditorSupport {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(FilterInvocationDefinitionSourceEditor.class);

    //~ Methods ================================================================

    public void setAsText(String s) throws IllegalArgumentException {
        FilterInvocationDefinitionMap source = new RegExpBasedFilterInvocationDefinitionMap();

        if ((s == null) || "".equals(s)) {
            // Leave target object empty
        } else {
            // Check if we need to override the default definition map
            if (s.lastIndexOf("PATTERN_TYPE_APACHE_ANT") != -1) {
                source = new PathBasedFilterInvocationDefinitionMap();

                if (logger.isDebugEnabled()) {
                    logger.debug(("Detected PATTERN_TYPE_APACHE_ANT directive; using Apache Ant style path expressions"));
                }
            }

            BufferedReader br = new BufferedReader(new StringReader(s));
            int counter = 0;
            String line;

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

                if (line.equals("CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON")) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Line " + counter
                            + ": Instructing mapper to convert URLs to lowercase before comparison");
                    }

                    source.setConvertUrlToLowercaseBeforeComparison(true);

                    continue;
                }

                if (line.lastIndexOf('=') == -1) {
                    continue;
                }

                // Tokenize the line into its name/value tokens
                String[] nameValue = StringUtils.delimitedListToStringArray(line, "=");
                String name = nameValue[0];
                String value = nameValue[1];

                if(!StringUtils.hasLength(name) || !StringUtils.hasLength(value)) {
                    throw new IllegalArgumentException("Failed to parse a valid name/value pair from " + line);
                }

                // Convert value to series of security configuration attributes
                ConfigAttributeEditor configAttribEd = new ConfigAttributeEditor();
                configAttribEd.setAsText(value);

                ConfigAttributeDefinition attr = (ConfigAttributeDefinition) configAttribEd
                    .getValue();

                // Register the regular expression and its attribute
                source.addSecureUrl(name, attr);
            }
        }

        setValue(source);
    }
}
