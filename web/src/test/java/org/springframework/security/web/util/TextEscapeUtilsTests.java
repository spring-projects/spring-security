package org.springframework.security.web.util;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.web.util.TextEscapeUtils;

public class TextEscapeUtilsTests {

    @Test
    public void charactersAreEscapedCorrectly() {
        assertEquals("a&lt;script&gt;&#034;&#039;", TextEscapeUtils.escapeEntities("a<script>\"'"));
    }
    
}
