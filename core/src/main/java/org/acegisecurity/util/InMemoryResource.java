package net.sf.acegisecurity.util;

import org.springframework.core.io.AbstractResource;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;

/**
 * An in memory implementation of Spring's {@link org.springframework.core.io.Resource} interface.
 * <p>
 * Used by the "Acegifier" web application to create a
 * bean factory from an XML string, rather than a file.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class InMemoryResource extends AbstractResource {

    ByteArrayInputStream in;
    String description;

    public InMemoryResource(String source) {
        this(source, null);
    }

    public InMemoryResource(String source, String description) {
        in = new ByteArrayInputStream(source.getBytes());
        this.description = description;
    }

    public String getDescription() {
        return description == null ? in.toString() : description;
    }

    public InputStream getInputStream() throws IOException {
        return in;
    }
}
