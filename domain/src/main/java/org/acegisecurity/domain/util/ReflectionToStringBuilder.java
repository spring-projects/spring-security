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

package net.sf.acegisecurity.domain.util;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Collection;

import net.sf.acegisecurity.domain.PersistableEntity;

import org.apache.commons.lang.builder.ToStringStyle;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * Customized Commons Lang <code>ReflectionToStringBuilder</code>
 * that ignores collections and inaccessible (ie lazy-loaded) fields.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @version $Id$
 */
public class ReflectionToStringBuilder
    extends org.apache.commons.lang.builder.ReflectionToStringBuilder {
    //~ Static fields/initializers =============================================

    protected final transient Log logger = LogFactory.getLog(getClass());

	private static DateFormat formatter = DateFormat.getDateTimeInstance();

    //~ Constructors ===========================================================

    public ReflectionToStringBuilder(Object object) {
        super(object, ToStringStyle.MULTI_LINE_STYLE);
    }

    //~ Methods ================================================================

    /**
     * Calendar fields are formatted with DateFormat.getDateTimeInstance()
     * instead of using Calendar.toString().
     *
     * @see org.apache.commons.lang.builder.ReflectionToStringBuilder#getValue(java.lang.reflect.Field)
     */
    protected Object getValue(Field f)
        throws IllegalArgumentException, IllegalAccessException {
        Object value = super.getValue(f);

        if (Calendar.class.isInstance(value)) {
            Calendar c = (Calendar) value;

            return formatter.format(c.getTime());
        } else {
            return value;
        }
    }
	
    protected boolean accept(Field field) {
		// Ignore if field inaccessible or collection
		try {
			Object o = getValue(field);
			if (o != null) {
				if (o instanceof PersistableEntity) {
					Serializable id = ((PersistableEntity)o).getInternalId();
					if (logger.isDebugEnabled()) {
						logger.debug(field + " id: " + id);
					}
				}
				if (o instanceof Collection) {
					int size = ((Collection)o).size();
					this.append(field.getName(), "<collection with " + size + " elements>");
					if (logger.isDebugEnabled()) {
						logger.debug(field + " size: " + size);
					}
				}
			}
		} catch (Exception fieldInaccessible) {
			this.append(field.getName(), "<inaccessible>");
			if (logger.isDebugEnabled()) {
				logger.debug("Inaccessible: " + field);
			}
			return false;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Accessible: " + field);
		}
		
        return true;
    }	
}
