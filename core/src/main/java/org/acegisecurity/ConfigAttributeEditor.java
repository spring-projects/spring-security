/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

import org.springframework.util.StringUtils;

import java.beans.PropertyEditorSupport;


/**
 * A property editor that can create a populated  {@link
 * ConfigAttributeDefinition} from a comma separated list of values.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConfigAttributeEditor extends PropertyEditorSupport {
    //~ Methods ================================================================

    public void setAsText(String s) throws IllegalArgumentException {
        if ((s == null) || "".equals(s)) {
            setValue(null);
        } else {
            String[] tokens = StringUtils.commaDelimitedListToStringArray(s);
            ConfigAttributeDefinition configDefinition = new ConfigAttributeDefinition();

            for (int i = 0; i < tokens.length; i++) {
                configDefinition.addConfigAttribute(new SecurityConfig(tokens[i]));
            }

            setValue(configDefinition);
        }
    }
}
