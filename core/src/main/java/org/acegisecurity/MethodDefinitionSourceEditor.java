/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.propertyeditors.PropertiesEditor;

import java.beans.PropertyEditorSupport;

import java.util.Iterator;
import java.util.Properties;


/**
 * Property editor to assist with the setup of  {@link MethodDefinitionSource}.
 * 
 * <p>
 * The class creates and populates an {@link MethodDefinitionMap}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionSourceEditor extends PropertyEditorSupport {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(MethodDefinitionSourceEditor.class);

    //~ Methods ================================================================

    public void setAsText(String s) throws IllegalArgumentException {
        MethodDefinitionMap source = new MethodDefinitionMap();

        if ((s == null) || "".equals(s)) {
            // Leave value in property editor null
        } else {
            // Use properties editor to tokenize the string
            PropertiesEditor propertiesEditor = new PropertiesEditor();
            propertiesEditor.setAsText(s);

            Properties props = (Properties) propertiesEditor.getValue();

            // Now we have properties, process each one individually
            ConfigAttributeEditor configAttribEd = new ConfigAttributeEditor();

            for (Iterator iter = props.keySet().iterator(); iter.hasNext();) {
                String name = (String) iter.next();
                String value = props.getProperty(name);

                // Convert value to series of security configuration attributes
                configAttribEd.setAsText(value);

                ConfigAttributeDefinition attr = (ConfigAttributeDefinition) configAttribEd
                                                 .getValue();

                // Register name and attribute
                source.addSecureMethod(name, attr);
            }
        }

        setValue(source);
    }
}
