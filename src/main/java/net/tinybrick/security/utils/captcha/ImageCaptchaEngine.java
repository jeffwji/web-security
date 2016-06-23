package net.tinybrick.security.utils.captcha;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Random;

import com.octo.captcha.CaptchaException;
import com.octo.captcha.CaptchaQuestionHelper;
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
import com.octo.captcha.image.ImageCaptcha;
import com.octo.captcha.image.gimpy.Gimpy;
import com.octo.captcha.image.gimpy.GimpyFactory;

public class ImageCaptchaEngine extends ListImageCaptchaEngine {
	public static String randomWords = "ABDEFGHJKLMNPQRTYabdefghijkmnpqrtuy23456789";
	public static Integer minAcceptedWordLength = 5;
	public static Integer maxAcceptedWordLength = 6;
	public static Boolean ignoreCase = true;

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
		if (ignoreCase) {
			this.addFactory(new GimpyCopyFactory(wordGenerator, wordToImage));
		}
		else {
			this.addFactory(new GimpyFactory(wordGenerator, wordToImage));
		}
	}

	public static class GimpyCopy extends ImageCaptcha implements Serializable {
		private static final long serialVersionUID = -1006419836261451303L;
		private String response;

		GimpyCopy(String question, BufferedImage challenge, String response) {
			super(question, challenge);
			this.response = response;
		}

		/**
		 * Validation routine from the CAPTCHA interface. this methods verify if the response is not null and a String
		 * and
		 * then compares the given response to the internal string.
		 *
		 * @return true if the given response equals the internal response, false otherwise.
		 */
		public final Boolean validateResponse(final Object response) {
			return (null != response && response instanceof String) ? validateResponse((String) response)
					: Boolean.FALSE;
		}

		/**
		 * Very simple validation routine that compares the given response to the internal string.
		 *
		 * @return true if the given response equals the internal response, false otherwise.
		 */
		private final Boolean validateResponse(final String response) {
			// 主要改的这里
			return new Boolean(response.toLowerCase().equals(this.response.toLowerCase()));
		}
	}

	public static class GimpyCopyFactory extends com.octo.captcha.image.ImageCaptchaFactory {
		private Random myRandom = new SecureRandom();
		private WordToImage wordToImage;
		private WordGenerator wordGenerator;

		public static final String BUNDLE_QUESTION_KEY = Gimpy.class.getName(); // 这个还是用原来的Gimpy

		public GimpyCopyFactory(WordGenerator generator, WordToImage word2image) {
			if (word2image == null) {
				throw new CaptchaException("Invalid configuration" + " for a GimpyFactory : WordToImage can't be null");
			}
			if (generator == null) {
				throw new CaptchaException("Invalid configuration"
						+ " for a GimpyFactory : WordGenerator can't be null");
			}
			wordToImage = word2image;
			wordGenerator = generator;

		}

		/**
		 * gimpies are ImageCaptcha
		 *
		 * @return the image captcha with default locale
		 */
		public ImageCaptcha getImageCaptcha() {
			return getImageCaptcha(Locale.getDefault());
		}

		public WordToImage getWordToImage() {
			return wordToImage;
		}

		public WordGenerator getWordGenerator() {
			return wordGenerator;
		}

		/**
		 * gimpies are ImageCaptcha
		 *
		 * @return a pixCaptcha with the question :"spell the word"
		 */
		@Override
		public ImageCaptcha getImageCaptcha(Locale locale) {

			//length
			Integer wordLength = getRandomLength();

			String word = getWordGenerator().getWord(wordLength, locale);

			BufferedImage image = null;
			try {
				image = getWordToImage().getImage(word);
			}
			catch (Throwable e) {
				throw new CaptchaException(e);
			}
			// 这里用我们自己写的GimpyCopy
			ImageCaptcha captcha = new GimpyCopy(CaptchaQuestionHelper.getQuestion(locale, BUNDLE_QUESTION_KEY), image,
					word);
			return captcha;
		}

		protected Integer getRandomLength() {
			Integer wordLength;
			int range = getWordToImage().getMaxAcceptedWordLength() - getWordToImage().getMinAcceptedWordLength();
			int randomRange = range != 0 ? myRandom.nextInt(range + 1) : 0;
			wordLength = new Integer(randomRange + getWordToImage().getMinAcceptedWordLength());
			return wordLength;
		}
	}
}
