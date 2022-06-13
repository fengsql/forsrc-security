package com.forsrc.security.configure;

import com.forsrc.security.config.ConfigSecurity;
import com.forsrc.security.decision.DecisionAccess;
import com.forsrc.security.filter.FilterAuthentication;
import com.forsrc.security.filter.FilterLogin;
import com.forsrc.security.decision.DecisionSecurityMetadataSource;
import com.forsrc.security.handler.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.Filter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class ConfigureWebSecurity extends WebSecurityConfigurerAdapter {

  @Value("${security.enable:false}")
  private boolean enable;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    configCommon(http);
    ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry = http.authorizeRequests();
    if (!enable) {
      registry.anyRequest().permitAll();
      return;
    }
    
    registry.antMatchers(HttpMethod.OPTIONS, "/**").anonymous();  //跨域预检请求
    
    setProcessor(registry);

    registry  //
      .anyRequest().authenticated()  // 剩下所有的验证都需要验证
      .and() //
      .addFilter(getLoginFilter()) //
      .addFilterBefore(filterAuthentication(), BasicAuthenticationFilter.class); //

    log.info("WebSecurityConfig ok.");
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    if (!enable) {
      web.ignoring().antMatchers("/**");
      return;
    }
    addPermit(web);
  }

  //  @Override
  //  protected void configure(AuthenticationManagerBuilder builder) throws Exception {
  //    builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
  //  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
    return source;
  }

  //  @Bean
  @Override
  public AuthenticationManager authenticationManager() throws Exception {
    return super.authenticationManager();
  }

  private Filter getLoginFilter() throws Exception {
    HandlerSecurityLogin handlerSecurityLogin = new HandlerSecurityLogin();
    handlerSecurityLogin.setAuthenticationManager(authenticationManager());
    return new FilterLogin(handlerSecurityLogin);
  }

  private void configCommon(HttpSecurity http) throws Exception {
    http //
      .csrf().disable()  //禁用 Spring Security 自带的跨域处理
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)  //禁用session
      .and()  //
      .headers().frameOptions().disable()  // 解决不允许显示在iframe的问题
      .cacheControl().disable()  // 禁用缓存
      .and()  //
      .exceptionHandling()  //
      .accessDeniedHandler(new HandlerAuthenticationDenied())  //登录后, 访问没有权限处理类
      .authenticationEntryPoint(new HandlerUnauthentication())  //匿名访问, 没有权限的处理类
      .and()  //
      .logout().logoutUrl(ConfigSecurity.security.logoutUrl).permitAll()  //退出登录
      .logoutSuccessHandler(new HandlerSecurityLogout());  //
  }

  private void addPermit(WebSecurity web) {
    if (ConfigSecurity.security.permit == null) {
      return;
    }
    web.ignoring().antMatchers(ConfigSecurity.security.permit.toArray(new String[0]));
  }

  private void setProcessor(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) {
    registry.withObjectPostProcessor(new SecurityObjectPostProcessor());
  }

  public FilterInvocationSecurityMetadataSource filterSecurityMetadataSource() {
    return new DecisionSecurityMetadataSource();
  }

  public DecisionAccess accessDecisionManager() {
    return new DecisionAccess();
  }

  private class SecurityObjectPostProcessor implements ObjectPostProcessor<FilterSecurityInterceptor> {
    @Override
    public <O extends FilterSecurityInterceptor> O postProcess(O fsi) {
      fsi.setSecurityMetadataSource(filterSecurityMetadataSource());
      fsi.setAccessDecisionManager(accessDecisionManager());
      return fsi;
    }

  }

  private FilterAuthentication filterAuthentication() {
    return new FilterAuthentication();
  }

}
