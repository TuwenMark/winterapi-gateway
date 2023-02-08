package com.winter;

import com.winter.api.demo.DemoService;
import org.apache.dubbo.config.annotation.DubboReference;
import org.apache.dubbo.config.spring.context.annotation.EnableDubbo;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Service;

/**
 * @author Mr.Ye
 */
@SpringBootApplication(exclude= DataSourceAutoConfiguration.class)
@Service
@EnableDubbo
public class WinterApiGatewayApplication {
	@DubboReference
	private DemoService demoService;

	public static void main(String[] args) {
		ConfigurableApplicationContext context = SpringApplication.run(WinterApiGatewayApplication.class, args);
		WinterApiGatewayApplication application = context.getBean(WinterApiGatewayApplication.class);
		String result = application.doSayHello("world");
		System.out.println("result: " + result);
	}

	public String doSayHello(String name) {
		return demoService.sayHello(name);
	}


}
