// Email Service for OTP and Notifications
class EmailService {
    constructor() {
        this.apiKey = 'your-emailjs-api-key';
        this.serviceId = 'your-emailjs-service-id';
        this.templateId = 'your-emailjs-template-id';
    }

    // Initialize EmailJS
    init() {
        emailjs.init(this.apiKey);
    }

    // Send OTP email
    async sendOTP(email, name, otp) {
        const templateParams = {
            to_email: email,
            to_name: name,
            otp_code: otp,
            company_name: 'CyberForensics Pro',
            message: `Your verification code is: ${otp}. This code will expire in 5 minutes.`
        };

        try {
            const response = await emailjs.send(
                this.serviceId,
                this.templateId,
                templateParams
            );
            console.log('OTP email sent successfully:', response);
            return true;
        } catch (error) {
            console.error('Failed to send OTP email:', error);
            return false;
        }
    }

    // Send welcome email
    async sendWelcomeEmail(email, name) {
        const templateParams = {
            to_email: email,
            to_name: name,
            company_name: 'CyberForensics Pro',
            message: `Welcome to CyberForensics Pro! Your account has been successfully created.`
        };

        try {
            const response = await emailjs.send(
                this.serviceId,
                'welcome_template',
                templateParams
            );
            console.log('Welcome email sent successfully:', response);
            return true;
        } catch (error) {
            console.error('Failed to send welcome email:', error);
            return false;
        }
    }

    // Send security alert email
    async sendSecurityAlert(email, name, alertType, details) {
        const templateParams = {
            to_email: email,
            to_name: name,
            alert_type: alertType,
            alert_details: details,
            company_name: 'CyberForensics Pro',
            timestamp: new Date().toLocaleString()
        };

        try {
            const response = await emailjs.send(
                this.serviceId,
                'security_alert_template',
                templateParams
            );
            console.log('Security alert sent successfully:', response);
            return true;
        } catch (error) {
            console.error('Failed to send security alert:', error);
            return false;
        }
    }
}

// Export email service
window.emailService = new EmailService();