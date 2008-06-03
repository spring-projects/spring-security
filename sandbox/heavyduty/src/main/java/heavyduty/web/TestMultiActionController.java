package heavyduty.web;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.multiaction.MultiActionController;

/**
 * Reproduces SEC-830.
 */
public class TestMultiActionController extends MultiActionController {
	public static final String VIEW_NAME = "multi-action-test";
	
	public String login(HttpServletRequest request, HttpServletResponse response) {
		return "login";
	}
		
	public void step1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		request.getRequestDispatcher("/testMulti.htm?action=step1xtra").forward(request, response);
	}

	public ModelAndView step1xtra(HttpServletRequest request, HttpServletResponse response) throws ServletRequestBindingException {
		return createView("step2");
	}	
	
	public ModelAndView step2(HttpServletRequest request, HttpServletResponse response) throws ServletRequestBindingException {
		return createView("step1");
	}
	
	private ModelAndView createView(String name) {
		Map model = new HashMap();
		model.put("nextAction", name);
		return new ModelAndView(VIEW_NAME, model);
	}
	
}

