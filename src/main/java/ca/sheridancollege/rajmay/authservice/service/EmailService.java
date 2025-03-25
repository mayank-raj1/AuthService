package com.example.auth.service;

import com.example.auth.entity.User;
import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;
import com.sendgrid.helpers.mail.objects.Personalization;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final SpringTemplateEngine templateEngine;
    private final SendGrid sendGrid;

    @Value("${app.sendgrid.from-email}")
    private String fromEmail;

    @Value("${app.sendgrid.from-name}")
    private String fromName;

    @Value("${app.auth.verificationUrl}")
    private String verificationBaseUrl;

    @Value("${app.auth.passwordResetUrl}")
    private String passwordResetBaseUrl;

    @Async
    public void sendVerificationEmail(User user, String token) {
        String url = verificationBaseUrl + "?token=" + token;
        String subject = "Please verify your email";

        Map<String, Object> variables = new HashMap<>();
        variables.put("name", user.getFirstName());
        variables.put("url", url);

        sendEmail(user.getEmail(), subject, "email-verification", variables);
    }

    @Async
    public void sendPasswordResetEmail(User user, String token) {
        String url = passwordResetBaseUrl + "?token=" + token;
        String subject = "Reset your password";

        Map<String, Object> variables = new HashMap<>();
        variables.put("name", user.getFirstName());
        variables.put("url", url);

        sendEmail(user.getEmail(), subject, "password-reset", variables);
    }

    private void sendEmail(String to, String subject, String templateName, Map<String, Object> variables) {
        try {
            // Process template with Thymeleaf
            Context context = new Context();
            context.setVariables(variables);
            String htmlContent = templateEngine.process(templateName, context);

            // Create SendGrid mail
            Email from = new Email(fromEmail, fromName);
            Email toEmail = new Email(to);
            Content content = new Content("text/html", htmlContent);
            Mail mail = new Mail();
            mail.setFrom(from);
            mail.setSubject(subject);
            
            // Set personalization
            Personalization personalization = new Personalization();
            personalization.addTo(toEmail);
            mail.addPersonalization(personalization);
            
            // Add content
            mail.addContent(content);

            // Send the email
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            
            Response response = sendGrid.api(request);
            
            if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
                log.info("Email sent successfully to: {}, status code: {}", to, response.getStatusCode());
            } else {
                log.error("Failed to send email to: {}, status code: {}, response body: {}", 
                        to, response.getStatusCode(), response.getBody());
            }
        } catch (IOException e) {
            log.error("Error sending email to: {}", to, e);
        }
    }
}
