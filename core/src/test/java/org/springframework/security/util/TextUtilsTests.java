package org.springframework.security.util;

import static org.junit.Assert.*;

import org.junit.Test;

public class TextUtilsTests {

    @Test
    public void charactersAreEscapedCorrectly() {
        assertEquals("a&lt;script&gt;&#034;&#039;", TextUtils.escapeEntities("a<script>\"'"));
    }
    
}
