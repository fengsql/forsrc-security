package com.forsrc.security.handler;

import com.forsrc.common.constant.Code;
import com.forsrc.common.tool.ToolResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class HandlerUnauthentication implements AuthenticationEntryPoint {
  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
    log.info("UnauthenticationHandler. url: {}. msg: {}", request.getRequestURI(), exception.getMessage());
    ToolResponse.error(response, Code.AUTHENTICATION_EXCEPTION);
  }
}