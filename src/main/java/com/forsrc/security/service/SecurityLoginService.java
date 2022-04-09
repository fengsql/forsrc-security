package com.forsrc.security.service;

import com.forsrc.common.tool.Tool;
import com.forsrc.common.tool.ToolJson;
import com.forsrc.security.model.AuthenticationToken;
import com.forsrc.security.model.LoginRequest;
import com.forsrc.security.model.SecurityUserDetails;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;

@Slf4j
public class SecurityLoginService {
  @Setter
  private UserDetailsService userDetailsService;
  @Setter
  private PasswordEncoder passwordEncoder;
  @Setter
  private AuthenticationManager authenticationManager;

  /**
   * 系统登录认证
   */
  @SneakyThrows
  public Authentication login(HttpServletRequest request) {
    String param = Tool.readStream(request.getInputStream());
    LoginRequest loginRequest = ToolJson.toBean(param, LoginRequest.class);
    return login(request, loginRequest);
  }

  private Authentication login(HttpServletRequest request, LoginRequest loginRequest) {
    UserDetails userDetails = getUserDetails(loginRequest);
    AuthenticationToken authenticationToken = getAuthenticationToken(request, userDetails, loginRequest);
    //验证登录，调用 loadUserByUsername 方法
    Authentication authentication = authenticationManager.authenticate(authenticationToken);
    SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    SecurityContextHolder.getContext().setAuthentication(authentication);  // 认证成功存储认证信息到上下文
    log.info("SecurityContextHolder.getContext().setAuthentication ok.");
    return authentication;
  }

  private AuthenticationToken getAuthenticationToken(HttpServletRequest request, UserDetails userDetails, LoginRequest loginRequest) {
    AuthenticationToken authenticationToken = new AuthenticationToken(userDetails, loginRequest.getPassword());
    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    return authenticationToken;
  }

  private UserDetails getUserDetails(LoginRequest loginRequest) {
    SecurityUserDetails securityUserDetails = new SecurityUserDetails();
    securityUserDetails.setUsername(loginRequest.getUsername());
    return securityUserDetails;
  }

}
