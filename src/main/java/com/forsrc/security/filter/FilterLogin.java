package com.forsrc.security.filter;

import com.forsrc.common.constant.Code;
import com.forsrc.common.exception.CommonException;
import com.forsrc.common.tool.ToolResponse;
import com.forsrc.security.base.BLoginResponse;
import com.forsrc.security.base.IUserDetails;
import com.forsrc.security.config.ConfigSecurity;
import com.forsrc.security.handler.HandlerSecurityLogin;
import com.forsrc.security.tool.ToolToken;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class FilterLogin extends UsernamePasswordAuthenticationFilter {

  private final HandlerSecurityLogin handlerSecurityLogin;
  @Setter
  private HandlerExceptionResolver resolver;

  public FilterLogin(HandlerSecurityLogin handlerSecurityLogin) {
    this.handlerSecurityLogin = handlerSecurityLogin;
    super.setFilterProcessesUrl(ConfigSecurity.security.loginUrl);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, CommonException {
    log.info("login start.");
    return handlerSecurityLogin.login(request, response);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
    IUserDetails userDetails = (IUserDetails) authentication.getPrincipal();
    String token = ToolToken.generateToken(authentication);
    BLoginResponse loginResponse = userDetails.getLoginResponse();
    loginResponse.setToken(token);
    ToolResponse.writeData(response, loginResponse);
    log.info("login ok. username: {}", userDetails.getUsername());
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
    log.info("login fail.", exception);
    Code code;
    if (exception instanceof AccountExpiredException) {
      //????????????
      code = Code.USER_ACCOUNT_EXPIRED;
    } else if (exception instanceof BadCredentialsException) {
      //????????????
      code = Code.USER_CREDENTIALS_ERROR;
    } else if (exception instanceof CredentialsExpiredException) {
      //????????????
      code = Code.USER_CREDENTIALS_EXPIRED;
    } else if (exception instanceof DisabledException) {
      //???????????????
      code = Code.USER_ACCOUNT_DISABLE;
    } else if (exception instanceof LockedException) {
      //????????????
      code = Code.USER_ACCOUNT_LOCKED;
    } else if (exception instanceof UsernameNotFoundException) {
      //???????????????
      code = Code.USER_ACCOUNT_NOT_EXIST;
    } else if (exception instanceof InternalAuthenticationServiceException) {
      //??????????????????
      code = Code.AUTHENTICATION_EXCEPTION;
    } else {
      //????????????
      code = Code.AUTHENTICATION_EXCEPTION;
    }
    ToolResponse.error(response, code);
  }

}
