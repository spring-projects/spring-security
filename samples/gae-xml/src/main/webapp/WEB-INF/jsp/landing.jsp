<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@page session="false" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">

<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <link rel="stylesheet" href="/static/css/gae.css" type="text/css" />
    <title>Spring Security GAE Sample</title>
  </head>

  <body>
  <div id="content">
  <h3>Spring Security GAE Application</h3>

  <p>
  This application demonstrates the integration of Spring Security
  with the services provided by Google App Engine. It shows how to:
  <ul>
      <li>Authenticate using Google Accounts.</li>
      <li>Implement "on&ndash;demand" authentication when a user accesses a secured resource.</li>
      <li>Supplement the information from Google Accounts with application&ndash;specific roles.</li>
      <li>Store user account data in an App Engine datastore using the native API.</li>
      <li>Setup access-control restrictions based on the roles assigned to users.</li>
      <li>Disable the accounts of specfic users to prevent access.</li>
  </ul>
  </p>
  <p>
  Go to the <a href="/home.htm">home page</a>.
  </p>
  </div>
  </body>
</html>
