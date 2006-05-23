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

package org.acegisecurity.domain.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.StringUtils;

import java.beans.PropertyEditorSupport;


/**
 * DOCUMENT ME!
 *
 * @author Ben Alex
 * @version $Id$
  */
public class EnumEditor extends PropertyEditorSupport {
    //~ Instance fields ================================================================================================

    private final Class<?extends Enum> enumClass;
    protected final transient Log log = LogFactory.getLog(getClass());
    private final boolean fallbackToNull;

    //~ Constructors ===================================================================================================

/**
         * Create a new EnumEditor, which can create an Enum by retrieving
         * the map of enum keys.
         * 
         * <p>The fallbackToNull indicates whether null should be returned if
         * a null String is provided to the property editor or if the provided
         * String could not be used to locate an Enum. If set to true, null
         * will be returned. If set to false, IllegalArgumentException will be thrown.
         */
    public <E extends Enum<E>>EnumEditor(Class<E> enumClass, boolean fallbackToNull) {
        this.enumClass = enumClass;
        this.fallbackToNull = fallbackToNull;
    }

    //~ Methods ========================================================================================================

    public String getAsText() {
        String result = null;

        if (getValue() != null) {
            result = ((Enum) getValue()).name();
        }

        if (log.isDebugEnabled()) {
            log.debug("Property Editor returning: " + result);
        }

        return result;
    }

    /**
     * Parse the Enum from the given text.
     *
     * @param text DOCUMENT ME!
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    @SuppressWarnings("unchecked")
    public void setAsText(String text) throws IllegalArgumentException {
        if (this.fallbackToNull && !StringUtils.hasText(text)) {
            // treat empty String as null value
            setValue(null);
        } else {
            Enum value = Enum.valueOf(this.enumClass, text);

            if (log.isDebugEnabled()) {
                log.debug("Property Editor converted '" + text + "' to object: " + value);
            }

            setValue(value);
        }
    }
}
