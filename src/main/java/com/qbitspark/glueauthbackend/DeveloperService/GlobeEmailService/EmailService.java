package com.qbitspark.glueauthbackend.DeveloperService.GlobeEmailService;

public interface EmailService {
   void sendAccountVerificationEmail(String to, String verificationLink);
   void sendPasswordResetEmail(String to, String resetLink);
}
