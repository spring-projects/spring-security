/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers.dao.memory;

import net.sf.acegisecurity.GrantedAuthorityImpl;

import org.springframework.util.StringUtils;

import java.beans.PropertyEditorSupport;


/**
 * Property editor that creates a {@link UserAttributeDefinition} from a  comma
 * separated list of values.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserAttributeEditor extends PropertyEditorSupport {
    //~ Methods ================================================================

    public void setAsText(String s) throws IllegalArgumentException {
        if ((s == null) || "".equals(s)) {
            setValue(null);
        } else {
            String[] tokens = StringUtils.commaDelimitedListToStringArray(s);
            UserAttributeDefinition userAttrib = new UserAttributeDefinition();

            for (int i = 0; i < tokens.length; i++) {
                String currentToken = tokens[i];

                if (i == 0) {
                    userAttrib.setPassword(currentToken);
                } else {
                    if (currentToken.toLowerCase().equals("enabled")) {
                        userAttrib.setEnabled(true);
                    } else if (currentToken.toLowerCase().equals("disabled")) {
                        userAttrib.setEnabled(false);
                    } else {
                        userAttrib.addAuthority(new GrantedAuthorityImpl(currentToken));
                    }
                }
            }

            if (userAttrib.isValid()) {
                setValue(userAttrib);
            } else {
                setValue(null);
            }
        }
    }
}
