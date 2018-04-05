package com.legalfab.cms;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.legalfab.cms.config.ConfigProperties;

@SpringBootApplication
public class Application extends SpringBootServletInitializer implements CommandLineRunner {
	
	@Autowired
    private ApplicationContext appContext;
	
	@Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(Application.class);
    }
	public static void main(String[] args) {
		
		SpringApplication.run(Application.class, args);
	}
	
	@Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
    @Override
    public void run(String... args) throws Exception
    {
    	ConfigProperties configProperties = (ConfigProperties) appContext.getBean("configProperties");
    }
    
}
