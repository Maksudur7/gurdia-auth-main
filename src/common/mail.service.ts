// src/common/services/mail.service.ts
import * as nodemailer from 'nodemailer';

export const sendOtpEmail = async (email: string, otp: string) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER, 
      pass: process.env.EMAIL_PASS, 
    },
  });

  const mailOptions = {
    from: `"Gurdia Support" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Your Verification OTP Code',
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>Security Verification</h2>
        <p>Hello,</p>
        <p>Your OTP code for logging into Gurdia App is:</p>
        <h1 style="color: #4CAF50;">${otp}</h1>
        <p>This code will expire in 5 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
};