package com.wang.security.authentication.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.wang.security.exception.InvalidCaptacheException;
import com.wang.utils.i18n.I18N;
import com.octo.captcha.service.image.ImageCaptchaService;

public class CaptchaAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	public static final String SPRING_SECURITY_FORM_CAPTCHA_KEY = "captcha";

	ImageCaptchaService captchaService;

	public ImageCaptchaService getCaptchaService() {
		return captchaService;
	}

	public void setCaptchaService(ImageCaptchaService captchaService) {
		this.captchaService = captchaService;
	}

	boolean captchaEnabled = true;

	public boolean isCaptchaEnabled() {
		return captchaEnabled;
	}

	public void setCaptchaEnabled(boolean captchaEnabled) {
		this.captchaEnabled = captchaEnabled;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		if (captchaEnabled) {
			logger.info("Check captcha.");
			checkCaptcha(request);
		}

		return super.attemptAuthentication(request, response);
	}

	protected void checkCaptcha(HttpServletRequest request) {
		String captcha = obtainCaptcha(request);
		logger.debug("Captcha: " + captcha);

		try {
			if (captcha == null || captcha.trim().length() == 0) {
				throw new InvalidCaptacheException(I18N.value("login.error.captcha"));
			}

			try {
				if (!captchaService.validateResponseForID(request.getSession().getId(), captcha))
					throw new InvalidCaptacheException(I18N.value("login.error.captcha"));
			}
			catch (Exception e) {
				throw new InvalidCaptacheException(I18N.value("login.error.captcha"));
			}
		}
		catch (InvalidCaptacheException e) {
			throw e;
		}
	}

	protected String obtainCaptcha(HttpServletRequest request) {
		return request.getParameter(SPRING_SECURITY_FORM_CAPTCHA_KEY);
	}
}
