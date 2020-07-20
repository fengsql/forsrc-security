package com.forsrc.security.config;

import com.forsrc.security.base.IUserDetailsService;
import com.forsrc.security.filter.AuthenticationFilter;
import com.forsrc.security.filter.LoginFilter;
import com.forsrc.security.handler.AuthenticationDeniedHandler;
import com.forsrc.security.handler.SecurityLogoutHandler;
import com.forsrc.security.handler.UnauthenticationHandler;
import com.forsrc.security.service.SecurityLoginService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.annotation.Resource;
import javax.servlet.Filter;
import java.util.List;
import java.util.Map;

//@ConditionalOnBean(IUserDetailsService.class)
//@ConditionalOnExpression("${security.enable:false}")
//@ConditionalOnClass(IUserDetailsService.class)
//@ConditionalOnExpression("#{'true'.equals(environment['security.enable'])}")
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Value("${security.enable:false}")
  private boolean enable;

  @Resource
  private AuthenticationDeniedHandler accessDeniedHandler;
  @Resource
  private UnauthenticationHandler unauthenticationHandler;
  @Resource
  private SecurityLogoutHandler logoutSuccessHandler;
  @Resource
  private IUserDetailsService userDetailsService;
  @Resource
  private PasswordEncoder passwordEncoder;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    if (!enable) {
      http.authorizeRequests().anyRequest().permitAll();
      return;
    }
    log.info("WebSecurityConfig start.");
    http //
      .csrf().disable()  //禁用 Spring Security 自带的跨域处理
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)  //禁用session
      .and()  //
      .headers().frameOptions().disable()  // 解决不允许显示在iframe的问题
      .and()  //
      .exceptionHandling()  //
      .accessDeniedHandler(accessDeniedHandler)  //登录后, 访问没有权限处理类
      .authenticationEntryPoint(unauthenticationHandler)  //匿名访问, 没有权限的处理类
      //      .and()  //
      //      .formLogin()  //
      //      //      .loginPage("/login")  //登录url请求路径
      //      .loginProcessingUrl("/auth/login").permitAll()  //登录接口
      //      .successHandler(loginSuccessHandler)  //登录成功
      //      .failureHandler(loginFailureHandler)  //登录失败
      .and()  //
      .logout().logoutUrl(ConfigSecurity.security.logoutUrl).permitAll()  //退出登录
      .logoutSuccessHandler(logoutSuccessHandler)  //
      .and() //
      .authorizeRequests().antMatchers(HttpMethod.OPTIONS, "/**").anonymous()  //跨域预检请求
      .and() //
      .authorizeRequests().antMatchers(HttpMethod.POST, "/api/**").permitAll();  //
    //静态资源
    //    http.authorizeRequests().antMatchers("/", "/*.html").permitAll();
    //角色
    //    http.authorizeRequests().antMatchers("/static/user/**").hasAnyRole("user");
    //    http.authorizeRequests().antMatchers("/static/admin/**").hasAnyRole("admin");
    addRole(http);
    //
    http.authorizeRequests()  //
      .anyRequest().authenticated()  // 剩下所有的验证都需要验证
//            .anyRequest().permitAll() //剩下所有的都通过
      .and() //
      .addFilter(getLoginFilter()) //
      .addFilter(getAuthenticationFilter()); //

    http.headers().cacheControl(); //禁用缓存
    log.info("WebSecurityConfig ok.");
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    if (!enable) {
      web.ignoring().antMatchers("/**");
      return;
    }
//    web.ignoring().antMatchers("/", "/*.html", "/**/*.js", "/**/*.css", "/**/*.jpg", "/**/*.png", "/**/*.gif", "/**.ico");
    addPermit(web);
    //swagger
//    web.ignoring().antMatchers("/v2/api-docs",  //
//      "/swagger-resources/**",  //
//      "/configuration/ui",  //
//      "/configuration/security",  //
//      "/swagger-ui.html/**",  //
//      "/webjars/**",  //
//      "/definitions/**");
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
    return source;
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManager() throws Exception {
    return super.authenticationManager();
  }

  private Filter getLoginFilter() throws Exception {
    PasswordEncoder passwordEncoder = getPasswordEncoder();
    SecurityLoginService securityLoginService = new SecurityLoginService();
    securityLoginService.setAuthenticationManager(authenticationManager());
    securityLoginService.setUserDetailsService(userDetailsService);
    securityLoginService.setPasswordEncoder(passwordEncoder);
    return new LoginFilter(securityLoginService);
  }

  private PasswordEncoder getPasswordEncoder() {
    if (passwordEncoder == null) {
      passwordEncoder = NoOpPasswordEncoder.getInstance();
    }
    return passwordEncoder;
  }

  private Filter getAuthenticationFilter() throws Exception {
    return new AuthenticationFilter(authenticationManager());
  }

  private void addPermit(WebSecurity web) {
    if (ConfigSecurity.security.permit == null) {
      return;
    }
    web.ignoring().antMatchers(ConfigSecurity.security.permit.toArray(new String[0]));
  }

  private void addRole(HttpSecurity http) throws Exception {
    if (ConfigSecurity.security.role == null) {
      return;
    }
    for (Map.Entry<String, List<String>> entry : ConfigSecurity.security.role.entrySet()) {
      String role = entry.getKey();
      List<String> path = entry.getValue();
      http.authorizeRequests().antMatchers(path.toArray(new String[0])).hasAnyRole(role);
    }
  }

}
