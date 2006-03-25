package org.acegisecurity.domain.util;

import java.beans.PropertyEditorSupport;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.StringUtils;

public class EnumEditor extends PropertyEditorSupport {
	protected final transient Log log = LogFactory.getLog(getClass());

	private final Class<? extends Enum> enumClass;

	private final boolean fallbackToNull;

	/**
	 * Create a new EnumEditor, which can create an Enum by retrieving
	 * the map of enum keys.
	 * 
	 * <p>The fallbackToNull indicates whether null should be returned if
	 * a null String is provided to the property editor or if the provided
	 * String could not be used to locate an Enum. If set to true, null
	 * will be returned. If set to false, IllegalArgumentException will be thrown.
	 */
	public <E extends Enum<E>> EnumEditor(Class<E> enumClass, boolean fallbackToNull) {
		this.enumClass = enumClass;
		this.fallbackToNull = fallbackToNull;
	}

	/**
	 * Parse the Enum from the given text.
	 */
	@SuppressWarnings("unchecked")
	public void setAsText(String text) throws IllegalArgumentException {
		if (this.fallbackToNull && !StringUtils.hasText(text)) {
			// treat empty String as null value
			setValue(null);
		}
		else {
			Enum value = Enum.valueOf(this.enumClass, text);
			
			if (log.isDebugEnabled()) {
				log.debug("Property Editor converted '" + text + "' to object: " + value);
			}
			setValue(value);
		}
	}
	
    public String getAsText() {
    	String result = null;
    	if (getValue() != null) {
    		result = ((Enum) getValue()).name();
    	}
    	if (log.isDebugEnabled())
    		log.debug("Property Editor returning: " + result);
    	return result;
    }
}
