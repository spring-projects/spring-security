package org.springframework.security.web.headers;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertSame;
import static org.springframework.test.util.MatcherAssertionErrors.assertThat;

/**
 * Test for the {@code StaticHeaderFactory}
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class StaticHeaderFactoryTest {

    @Test
    public void sameHeaderShouldBeReturned() {
        StaticHeaderFactory factory = new StaticHeaderFactory("X-header", "foo");
        Header header = factory.create(null, null);
        assertThat(header.getName(), is("X-header"));
        assertThat(header.getValues()[0], is("foo"));

        assertSame(header, factory.create(null, null));
    }
}
