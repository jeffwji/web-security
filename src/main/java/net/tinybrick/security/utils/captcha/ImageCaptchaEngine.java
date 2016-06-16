package net.tinybrick.security.utils.captcha;

import java.awt.Color;

import com.octo.captcha.component.image.backgroundgenerator.BackgroundGenerator;
import com.octo.captcha.component.image.backgroundgenerator.GradientBackgroundGenerator;
import com.octo.captcha.component.image.fontgenerator.FontGenerator;
import com.octo.captcha.component.image.fontgenerator.TwistedRandomFontGenerator;
import com.octo.captcha.component.image.textpaster.RandomTextPaster;
import com.octo.captcha.component.image.textpaster.TextPaster;
import com.octo.captcha.component.image.wordtoimage.ComposedWordToImage;
import com.octo.captcha.component.image.wordtoimage.WordToImage;
import com.octo.captcha.component.word.wordgenerator.RandomWordGenerator;
import com.octo.captcha.component.word.wordgenerator.WordGenerator;
import com.octo.captcha.engine.image.ListImageCaptchaEngine;
import com.octo.captcha.image.gimpy.GimpyFactory;

public class ImageCaptchaEngine extends ListImageCaptchaEngine {
	public static String randomWords = "ABDEFGHJKLMNPQRTYabdefghijkmnpqrtuy23456789";
	public static Integer minAcceptedWordLength = 5;
	public static Integer maxAcceptedWordLength = 6;

	@Override
	protected void buildInitialFactories() {
		// capital letters only, 
		WordGenerator wordGenerator = new RandomWordGenerator(randomWords);

		// 5 or 6 characters
		TextPaster textPaster = new RandomTextPaster(minAcceptedWordLength, maxAcceptedWordLength, Color.WHITE);

		//funky background
		BackgroundGenerator backgroundGenerator = new GradientBackgroundGenerator(new Integer(220), new Integer(40),
				Color.RED, Color.CYAN);

		FontGenerator fontGenerator = new TwistedRandomFontGenerator(new Integer(14), new Integer(20));
		WordToImage wordToImage = new ComposedWordToImage(fontGenerator, backgroundGenerator, textPaster);
		this.addFactory(new GimpyFactory(wordGenerator, wordToImage));
	}
}
