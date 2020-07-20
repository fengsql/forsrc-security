package com.forsrc.security.handler;

import com.forsrc.common.constant.Code;
import com.forsrc.common.tool.ToolResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//@ConditionalOnExpression("${security.enable:false}")
@Component
@Slf4j
public class AuthenticationDeniedHandler implements AccessDeniedHandler {

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception) throws IOException {
    log.info("AccessDeniedException. url: {}. msg: {}", request.getRequestURI(), exception.getMessage());
    ToolResponse.error(response, Code.AUTHENTICATION_DENY);
  }

}