package com.forsrc.security.filter;

import com.forsrc.security.tool.ToolSecurity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebFilter(filterName = "tokenHeaderFilter", urlPatterns = "/api/**/*")
@Component
@Slf4j
public class TokenHeaderFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    log.info("TokenHeaderFilter."); 
    ToolSecurity.setAuthentication(request);
    filterChain.doFilter(request, response);
  }
}