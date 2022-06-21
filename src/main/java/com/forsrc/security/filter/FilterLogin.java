package com.forsrc.security.filter;

import com.forsrc.common.constant.Code;
import com.forsrc.common.tool.ToolResponse;
import com.forsrc.security.base.BLoginResponse;
import com.forsrc.security.base.IUserDetails;
import com.forsrc.security.config.ConfigSecurity;
import com.forsrc.security.handler.HandlerSecurityLogin;
import com.forsrc.security.tool.ToolToken;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class FilterLogin extends UsernamePasswordAuthenticationFilter {

  private final HandlerSecurityLogin handlerSecurityLogin;

  public FilterLogin(HandlerSecurityLogin handlerSecurityLogin) {
    this.handlerSecurityLogin = handlerSecurityLogin;
    super.setFilterProcessesUrl(ConfigSecurity.security.loginUrl);
  }

  @SneakyThrows
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    log.info("login start.");
    return handlerSecurityLogin.login(request);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
    IUserDetails userDetails = (IUserDetails) authentication.getPrincipal();
    String token = ToolToken.generateToken(authentication);
    BLoginResponse loginResponse = userDetails.getLoginResponse();
    loginResponse.setToken(token);
    ToolResponse.writeBody(response, loginResponse);
    log.info("login ok. username: {}", userDetails.getUsername());
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
    log.info("login fail.", exception);
    Code code;
    if (exception instanceof AccountExpiredException) {
      //账号过期
      code = Code.USER_ACCOUNT_EXPIRED;
    } else if (exception instanceof BadCredentialsException) {
      //密码错误
      code = Code.USER_CREDENTIALS_ERROR;
    } else if (exception instanceof CredentialsExpiredException) {
      //密码过期
      code = Code.USER_CREDENTIALS_EXPIRED;
    } else if (exception instanceof DisabledException) {
      //账号不可用
      code = Code.USER_ACCOUNT_DISABLE;
    } else if (exception instanceof LockedException) {
      //账号锁定
      code = Code.USER_ACCOUNT_LOCKED;
    } else if (exception instanceof UsernameNotFoundException) {
      //用户不存在
      code = Code.USER_ACCOUNT_NOT_EXIST;
    } else if (exception instanceof InternalAuthenticationServiceException) {
      //授权内部错误
      code = Code.AUTHENTICATION_EXCEPTION;
    } else {
      //其他错误
      code = Code.AUTHENTICATION_EXCEPTION;
    }
    ToolResponse.error(response, code);
  }

}
