package com.forsrc.security.handler;

import com.forsrc.common.tool.ToolResponse;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//@ConditionalOnExpression("${security.enable:false}")
@Component
@Slf4j
@EqualsAndHashCode(callSuper = false)
public class SecurityLogoutHandler implements LogoutSuccessHandler {

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    log.info("onLogoutSuccess ok.");
    ToolResponse.write(response, "注销成功");
  }

}