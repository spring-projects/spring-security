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

package org.acegisecurity.domain.service;

import org.acegisecurity.domain.PersistableEntity;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.beans.PropertyEditorSupport;


/**
 * Converts between a PersistableEntity's internal ID (expressed as a String and the corresponding
 * PersistableEntity sourced from an ImmutableManager).
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ImmutableManagerEditor extends PropertyEditorSupport {
    //~ Instance fields ================================================================================================

    private ImmutableManager immutableManager;
    protected final transient Log log = LogFactory.getLog(getClass());
    private final boolean fallbackToNull;

    //~ Constructors ===================================================================================================

    public ImmutableManagerEditor(ImmutableManager immutableManager, boolean fallbackToNull) {
        Assert.notNull(immutableManager, "ImmutableManager required");
        this.immutableManager = immutableManager;
        this.fallbackToNull = fallbackToNull;
    }

    //~ Methods ========================================================================================================

    public String getAsText() {
        String result = null;

        if (getValue() != null) {
            result = ((PersistableEntity) getValue()).getInternalId().toString();
        }

        if (log.isDebugEnabled()) {
            log.debug("Property Editor returning: " + result);
        }

        return result;
    }

    public void setAsText(String text) throws IllegalArgumentException {
        if (this.fallbackToNull && !StringUtils.hasText(text)) {
            // treat empty String as null value
            setValue(null);
        } else {
            Long id = new Long(text);
            PersistableEntity value = immutableManager.readId(id);

            if (log.isDebugEnabled()) {
                log.debug("Property Editor converted '" + text + "' to object: " + value);
            }

            setValue(value);
        }
    }
}
