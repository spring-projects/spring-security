/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.dao.memory;

import net.sf.acegisecurity.GrantedAuthorityImpl;

import org.springframework.util.StringUtils;

import java.beans.PropertyEditorSupport;


/**
 * Property editor that creates a {@link UserAttribute} from a  comma separated
 * list of values.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserAttributeEditor extends PropertyEditorSupport {
    //~ Methods ================================================================

    public void setAsText(String s) throws IllegalArgumentException {
        if (StringUtils.hasText(s)) {
            String[] tokens = StringUtils.commaDelimitedListToStringArray(s);
            UserAttribute userAttrib = new UserAttribute();

            for (int i = 0; i < tokens.length; i++) {
                String currentToken = tokens[i].trim();

                if (i == 0) {
                    userAttrib.setPassword(currentToken);
                } else {
                    if (currentToken.toLowerCase().equals("enabled")) {
                        userAttrib.setEnabled(true);
                    } else if (currentToken.toLowerCase().equals("disabled")) {
                        userAttrib.setEnabled(false);
                    } else {
                        userAttrib.addAuthority(new GrantedAuthorityImpl(
                                currentToken));
                    }
                }
            }

            if (userAttrib.isValid()) {
                setValue(userAttrib);
            } else {
                setValue(null);
            }
        } else {
            setValue(null);
        }
    }
}
