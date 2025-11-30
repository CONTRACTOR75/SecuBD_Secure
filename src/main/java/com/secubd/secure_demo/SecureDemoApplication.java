package com.secubd.secure_demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent ;
import org.springframework.context.event.EventListener ;

@SpringBootApplication
public class SecureDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureDemoApplication.class, args);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void serverReady() {
        System.out.println(" ");
        System.out.println("════════════════════════════════════════════════════════════════════════════════════════╗");
        System.out.println(" ");
        System.out.println("       SERVEUR EN VERSION SÉCURISÉE LANCÉE sur le port : http://localhost:8081 ");
        System.out.println(" ");
        System.out.println("════════════════════════════════════════════════════════════════════════════════════════╝");
        System.out.println(" ");
    }
}
