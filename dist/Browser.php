<?php
namespace Coercive\Utility\Browser;

/**
 * Class Browser
 *
 * @package		Coercive\Utility\Browser
 * @link		https://github.com/Coercive/browser
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2025 Anthony Moral
 * @license 	MIT
 */
class Browser
{
	/** @var string User Agent */
	private string $ua;

	/**
	 * Browser constructor.
	 *
	 * @return void
	 */
	public function __construct()
	{
		# User Agent from server
		$this->ua = (string) filter_input(INPUT_SERVER, 'HTTP_USER_AGENT', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * @param string $ua
	 * @return $this
	 */
	public function setUserAgent(string $ua): self
	{
		$this->ua = $ua;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getUserAgent(): string
	{
		return $this->ua;
	}
}