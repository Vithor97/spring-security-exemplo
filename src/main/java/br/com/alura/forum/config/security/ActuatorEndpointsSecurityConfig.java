package br.com.alura.forum.config.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@Order(-1)
public class ActuatorEndpointsSecurityConfig extends WebSecurityConfigurerAdapter {
	

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		System.out.println("Oiiiiii");
		auth.inMemoryAuthentication()
        .withUser("ana")
        .password("{noop}ana")
        .roles("admin")
        .and()
        .withUser("vitor")
        .password("{noop}123")
        .roles("user");  
		
	}

	  @Override
      protected void configure(HttpSecurity http) throws Exception {                  

           http.requestMatchers().antMatchers("/actuator/**")
           .and()
           .authorizeRequests()
           .antMatchers("/actuator/health").hasRole("admin")
           .antMatchers("/actuator/info").hasAnyRole("admin","user")
           .antMatchers("/actuator").permitAll()
           .anyRequest().hasAnyRole("admin")
           .and().csrf().disable()
           .httpBasic().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
  
           
      }
}
