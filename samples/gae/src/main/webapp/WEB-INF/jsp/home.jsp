<%@ page import="com.google.appengine.api.users.UserServiceFactory" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">

<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <link rel="stylesheet" href="/static/css/gae.css" type="text/css" />
    <title>Home Page</title>
  </head>
  <body>
  <div id="content">
     <h3>The Home Page</h3>
     <p>Welcome back <sec:authentication property="principal.nickname"/>.</p>
     <p>
     You can get to this page if you have authenticated and are a registered user.
     You are registered as
     <sec:authentication property="principal.forename"/> <sec:authentication property="principal.surname"/>.
     </p>
     <p>
     <a href="/logout.htm">Logout</a>.
     </p>
  </div>
  </body>
</html>
