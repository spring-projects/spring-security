package org.springframework.security.web.util;


/**
 * Interface for handlers extracting the cause out of a specific {@link Throwable} type.
 * 
 * @author Andreas Senft
 * @since 2.0
 * @version $Id$
 * 
 * @see ThrowableAnalyzer
 */
public interface ThrowableCauseExtractor {

    /**
     * Extracts the cause from the provided <code>Throwable</code>.
     * 
     * @param throwable the <code>Throwable</code>
     * @return the extracted cause (maybe <code>null</code>)
     * 
     * @throws IllegalArgumentException if <code>throwable</code> is <code>null</code> 
     * or otherwise considered invalid for the implementation
     */
    Throwable extractCause(Throwable throwable);
}
