package org.springframework.security.itest.web;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class TestController {

    @RequestMapping(value="/secure/file?with?special?chars.htm", method=RequestMethod.GET)
    public void sec1255TestUrl(HttpServletResponse response) throws IOException {
        response.getWriter().append("I'm file?with?special?chars.htm");
    }

}
