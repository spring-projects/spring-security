<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html
     PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
     "https://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>
    <title>A secure page</title>
  </head>
  <body>
    <jsp:include page="secure1body.jsp">
        <jsp:param name="x" value="1" />
        <jsp:param name="y" value="2" />
    </jsp:include>
  </body>
</html>