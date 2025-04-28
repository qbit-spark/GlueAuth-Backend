package com.qbitspark.glueauthbackend.DeveloperService.GlobeEmailService.IMPL;

import com.qbitspark.glueauthbackend.DeveloperService.GlobeEmailService.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.logging.Logger;

@RequiredArgsConstructor
@Service
public class EmailServiceIMPL implements EmailService {
    @Value("${spring.mail.username}")
    private String fromEmail;

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;


    @Override
    public void sendAccountVerificationEmail(String to, String verificationLink) {
        try {
            // Prepare the Thymeleaf context
            Context context = new Context();
            context.setVariable("userName", extractUsername(to));
            context.setVariable("verificationLink", verificationLink);

            // Process the template
            String htmlContent = templateEngine.process("verification-email", context);

            // Send email
            sendEmailWithHtmlContent(to, "Verify Your Account", htmlContent);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send verification email", e);
        }
    }

    @Override
    public void sendPasswordResetEmail(String to, String resetLink) {
        try {
            // Prepare the Thymeleaf context
            Context context = new Context();
            context.setVariable("userName", extractUsername(to));
            context.setVariable("resetLink", resetLink);
            context.setVariable("expiryTime", "1 hour"); // Configurable if needed

            // Process the template
            String htmlContent = templateEngine.process("password-reset-email", context);

            // Send email
            sendEmailWithHtmlContent(to, "Reset Your Password", htmlContent);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send password reset email", e);
        }
    }




    void sendEmailWithTemplate(String to, String subject, String templateName, Object model) {
        try {
            Context context = new Context();

            // If model is a Map, add all entries to the context
            if (model instanceof Map) {
                ((Map<String, Object>) model).forEach(context::setVariable);
            }

            String htmlContent = templateEngine.process(templateName, context);
            sendEmailWithHtmlContent(to, subject, htmlContent);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send email with template", e);
        }
    }

    void sendEmailWithHtmlContent(String to, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(
                    message,
                    MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                    StandardCharsets.UTF_8.name()
            );

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);

        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send HTML email", e);
        }
    }

    void sendEmail(String to, String subject, String body) {
        try {
            sendEmailWithHtmlContent(to, subject, "<html><body>" + body + "</body></html>");
        } catch (Exception e) {
            throw new RuntimeException("Failed to send email", e);
        }
    }

    // Utility method to extract username from email address
    private String extractUsername(String email) {
        return email.split("@")[0];
    }

}
