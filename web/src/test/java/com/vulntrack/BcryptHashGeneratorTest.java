package com.vulntrack;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class BcryptHashGeneratorTest {

    @Test
    void printHashes() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        System.out.println("admin:" + encoder.encode("AdminSecret123"));
        System.out.println("analyst:" + encoder.encode("AnalystSecret123"));
        System.out.println("engineer:" + encoder.encode("EngineerSecret123"));
        System.out.println("viewer:" + encoder.encode("ViewerSecret123"));
    }
}
