/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers.dao.memory;

import net.sf.acegisecurity.providers.dao.User;

import org.springframework.beans.propertyeditors.PropertiesEditor;

import java.beans.PropertyEditorSupport;

import java.util.Iterator;
import java.util.Properties;


/**
 * Property editor to assist with the setup of a {@link UserMap}.
 * 
 * <p>
 * The format of entries should be:
 * </p>
 * 
 * <p>
 * <code>
 * username=password,grantedAuthority[,grantedAuthority][,enabled|disabled]
 * </code>
 * </p>
 * 
 * <p>
 * The <code>password</code> must always be the first entry after the equals.
 * The <code>enabled</code> or <code>disabled</code> keyword can appear
 * anywhere (apart from the first entry reserved for the password). If neither
 * <code>enabled</code> or <code>disabled</code> appear, the default is
 * <code>enabled</code>. At least one granted authority must be listed.
 * </p>
 * 
 * <p>
 * The <code>username</code> represents the key and duplicates are handled the
 * same was as duplicates would be in Java <code>Properties</code> files.
 * </p>
 * 
 * <p>
 * If the above requirements are not met, the invalid entry will be silently
 * ignored.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserMapEditor extends PropertyEditorSupport {
    //~ Methods ================================================================

    public void setAsText(String s) throws IllegalArgumentException {
        UserMap userMap = new UserMap();

        if ((s == null) || "".equals(s)) {
            // Leave value in property editor null
        } else {
            // Use properties editor to tokenize the string
            PropertiesEditor propertiesEditor = new PropertiesEditor();
            propertiesEditor.setAsText(s);

            Properties props = (Properties) propertiesEditor.getValue();

            // Now we have properties, process each one individually
            UserAttributeEditor configAttribEd = new UserAttributeEditor();

            for (Iterator iter = props.keySet().iterator(); iter.hasNext();) {
                String username = (String) iter.next();
                String value = props.getProperty(username);

                // Convert value to a password, enabled setting, and list of granted authorities
                configAttribEd.setAsText(value);

                UserAttributeDefinition attr = (UserAttributeDefinition) configAttribEd
                                               .getValue();

                // Make a user object, assuming the properties were properly provided
                if (attr != null) {
                    User user = new User(username, attr.getPassword(),
                                         attr.isEnabled(), attr.getAuthorities());
                    userMap.addUser(user);
                }
            }
        }

        setValue(userMap);
    }
}
