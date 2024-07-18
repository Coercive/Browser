<?php
namespace Coercive\Utility\Browser;

/**
 * Class Ip
 *
 * @package		Coercive\Utility\Browser
 * @link		https://github.com/Coercive/browser
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2022 Anthony Moral
 * @license 	MIT
 */
class Ip
{
	/**
	 * @source https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php#answer-42269989
	 * @author Php'RegEx https://stackoverflow.com/users/7558876/phpregex
	 */
	const PATTERN_CIDR = '`^(?:((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))\.((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))\.((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))\.((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))(?:/((?:(?:0)|(?:3[0-2])|(?:[1-2]?[0-9]))))?)$`';

	/** @var string SERVER: REMOTE_ADDR entry */
	private string $_REMOTE_ADDR;

	/** @var string SERVER: HTTP_X_FORWARDED_FOR entry */
	private string $_HTTP_X_FORWARDED_FOR;

	/**
	 * Ip constructor.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$this->_REMOTE_ADDR = (string) filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$this->_HTTP_X_FORWARDED_FOR = (string) filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * Validate IPV4 or CIDR
	 *
	 * @param string $ipv4
	 * @param bool $cidr [optional]
	 * @return bool
	 */
	public function check(string $ipv4, bool $cidr = false): bool
	{
		if($cidr && !strpos($ipv4, '/')) {
			return false;
		}
		return $ipv4 && preg_match(self::PATTERN_CIDR, $ipv4);
	}

	/**
	 * Get current client ip
	 *
	 * @param bool $forwarded [optional]
	 * @return string
	 */
	public function getIp(bool $forwarded = true): string
	{
		$ip = $forwarded && $this->_HTTP_X_FORWARDED_FOR ? $this->_HTTP_X_FORWARDED_FOR : $this->_REMOTE_ADDR;

		# Deep ip from router
		$ip = str_replace(' ', ',', $ip);
		if(false !== $pos = strrpos($ip, ',')) {
			$ip = substr($ip, $pos +1);
		}

		return $ip;
	}

	/**
	 * Check if the given ipv4 is between given range
	 *
	 * @param string $ipv4 - IPV4 format : 127.0.0.1
	 * @param string $startIP - IPV4 format : 127.0.0.1
	 * @param string $endIP - IPV4 format : 127.0.0.1
	 * @return bool
	 */
	public function isBetween(string $ipv4, string $startIP, string $endIP): bool
	{
		$ipLong = ip2long($ipv4);
		$startLong = ip2long($startIP);
		$endLong = ip2long($endIP);

		if ($ipLong === false || $startLong === false || $endLong === false) {
			return false;
		}

		return ($ipLong >= $startLong && $ipLong <= $endLong);
	}

	/**
	 * Check if the given ipv4 belongs to given list of cidr
	 *
	 * @source https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php#answer-42269989
	 * @author Php'RegEx https://stackoverflow.com/users/7558876/phpregex
	 *
	 * @param string $ipv4 - IPV4 format : 127.0.0.1
	 * @param string[] $cidrs - List of IP/CIDR netmask : 127.0.0.0/24
	 * @return bool
	 */
	public function isInRange(string $ipv4, array $cidrs): bool
	{
		# Validate IP first
		if(!$this->check($ipv4)) {
			return false;
		}

		# Convert to dec
		if(!$ip = ip2long($ipv4)) {
			return false;
		}

		# This code is checking if a given ip belongs to given cidr list
		foreach($cidrs as $cidr) {
			if(!$range = $this->cidrToRange($cidr)) {
				continue;
			}
			if($ip >= $range['ip_min_dec'] && $ip <= $range['ip_max_dec']) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Convert CIDR to RANGE IP
	 *
	 * @source https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php#answer-42269989
	 * @author Php'RegEx https://stackoverflow.com/users/7558876/phpregex
	 *
	 * @param $ipv4
	 * @return array{ip_min_dec: int, ip_max_dec: int, ip_min: string, ip_max: string, subnet: string, wildcard: string, count: int}
	 */
	public function cidrToRange(string $ipv4): array
	{
		# Validate IP first
		if(!$this->check($ipv4)) {
			return [];
		}

		# Convert CIDR
		if ($pos = strpos($ipv4,'/')) {
			$n_ip = (1<<(32-substr($ipv4,1 + $pos))) -1;
			$ip_dec = ip2long(substr($ipv4,0, $pos));
		}

		# Ip v4 only
		else {
			$n_ip = 0;
			$ip_dec = ip2long($ipv4);
		}

		# Define range
		$ip_min = $ip_dec & ~$n_ip;
		$ip_max = $ip_min + $n_ip;

		# Different formats
		return [
			'ip_min_dec' => $ip_min,
			'ip_max_dec' => $ip_max,
			'ip_min' => long2ip($ip_min),
			'ip_max' => long2ip($ip_max),
			'subnet' => long2ip(~$n_ip),
			'wildcard' => long2ip($n_ip),
			'count' => ++$n_ip,
		];
	}

	/**
	 * Convert CIDR to FULL RANGE IP
	 *
	 * @source https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php#answer-42269989
	 * @author Php'RegEx https://stackoverflow.com/users/7558876/phpregex
	 *
	 * @param string $ipv4
	 * @return array
	 */
	public function cidrToFullRange(string $ipv4): array
	{
		# Calculate range infos
		$range = $this->cidrToRange($ipv4);
		if(!$range) {
			return [];
		}

		# Increment list
		$list = [];
		for($ip_dec = $range['ip_min_dec']; $ip_dec <= $range['ip_max_dec']; $ip_dec++) {
			$list[$ip_dec] = long2ip($ip_dec);
		}
		return $list;
	}

	/**
	 * Check if IP is in given domain list - with optional reverse check
	 *
	 * @param string $ip
	 * @param array $domains
	 * @param bool $reverse [optional]
	 * @return bool
	 */
	public function isIpMatchDomains(string $ip, array $domains, bool $reverse = false): bool
	{
		# Get hostname
		$hostname = gethostbyaddr($ip);
		if(!$hostname) {
			return false;
		}

		# Detect if in domains list
		$founded = false;
		foreach ($domains as $domain) {
			if (preg_match('`' . preg_quote($domain, '$`') . '`', $hostname)) {
				$founded = true;
				break;
			}
		}
		if(!$founded) {
			return false;
		}

		# Reverse match
		if(!$reverse) {
			return true;
		}
		$hosts = gethostbynamel($hostname) ?: [];
		foreach ($hosts as $host) {
			if($host === $ip) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Convert a range of IP addresses to CIDR notation.
	 *
	 * @param string $startIP The starting IP address of the range.
	 * @param string $endIP The ending IP address of the range.
	 * @return array An array of CIDR notations.
	 */
	public function rangeToCIDR(string $startIP, string $endIP): array
	{
		$start = ip2long($startIP);
		$end = ip2long($endIP);
		$cidrList = [];

		while ($end >= $start) {
			$maxSize = 32;
			while ($maxSize > 0) {
				$mask = (1 << (32 - $maxSize)) - 1;
				$maskBase = $start & ~$mask;
				if ($maskBase != $start) {
					break;
				}
				$maxSize--;
			}

			$maxDiff = 32 - (int) floor(log($end - $start + 1) / log(2));
			if ($maxSize < $maxDiff) {
				$maxSize = $maxDiff;
			}

			$cidr = long2ip($start) . '/' . $maxSize;
			$cidrList[] = $cidr;
			$start += 1 << (32 - $maxSize);
		}

		return $cidrList;
	}

	/**
	 * Calculate the number of IP addresses in a given CIDR block.
	 *
	 * @param string $cidr The CIDR block (e.g., "192.168.1.0/24").
	 * @return int The number of IP addresses in the CIDR block.
	 */
	public function countIPsInCIDR(string $cidr): int
	{
		if($mask = explode('/', $cidr)[1] ?? null) {
			return 1 << (32 - (int) $mask);
		}
		return 1;
	}

	/**
	 * Calculate the number of IP addresses in a given IP range.
	 *
	 * @param string $startIP The starting IP address of the range.
	 * @param string $endIP The ending IP address of the range.
	 * @return int The number of IP addresses in the range.
	 */
	public function countIPsInRange(string $startIP, string $endIP): int
	{
		$start = ip2long($startIP);
		$end = ip2long($endIP);

		if ($start === false || $end === false || $start > $end) {
			return 0;
		}
		return ($end - $start + 1);
	}
}