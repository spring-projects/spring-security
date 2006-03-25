package org.acegisecurity.domain.service;

import java.beans.PropertyEditorSupport;

import org.acegisecurity.domain.PersistableEntity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Converts between a PersistableEntity's internal ID (expressed as a String
 * and the corresponding PersistableEntity sourced from an ImmutableManager).
 *  
 * @author Ben Alex
 * @version $Id$
 */
public class ImmutableManagerEditor extends PropertyEditorSupport {
	protected final transient Log log = LogFactory.getLog(getClass());
	private ImmutableManager immutableManager;
	
	private final boolean fallbackToNull;

	public ImmutableManagerEditor(ImmutableManager immutableManager, boolean fallbackToNull) {
		Assert.notNull(immutableManager, "ImmutableManager required");
		this.immutableManager = immutableManager;
		this.fallbackToNull = fallbackToNull;
	}

	public void setAsText(String text) throws IllegalArgumentException {
		if (this.fallbackToNull && !StringUtils.hasText(text)) {
			// treat empty String as null value
			setValue(null);
		}
		else {
			Long id = new Long(text);
			PersistableEntity value = immutableManager.readId(id);
			
			if (log.isDebugEnabled()) {
				log.debug("Property Editor converted '" + text + "' to object: " + value);
			}
			setValue(value);
		}
	}
	
    public String getAsText() {
    	String result = null;
    	if (getValue() != null) {
    		result = ((PersistableEntity) getValue()).getInternalId().toString();
    	}
    	if (log.isDebugEnabled())
    		log.debug("Property Editor returning: " + result);
    	return result;
    }
}
