package com.hortonworks.whoville;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
public class WhovilleUI {
	
	public static void main(String[] args) {
		ApplicationContext app = SpringApplication.run(WhovilleUI.class, args);
	}
}
