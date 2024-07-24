<?php
namespace Coercive\Utility\Browser;

use GMP;
use InvalidArgumentException;

/**
 * Class Ip
 *
 * @package		Coercive\Utility\Browser
 * @link		https://github.com/Coercive/browser
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2024 Anthony Moral
 * @license 	MIT
 */
class Ip
{
	/**
	 * @source https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php#answer-42269989
	 * @author Php'RegEx https://stackoverflow.com/users/7558876/phpregex
	 */
	const PATTERN_IPV4_CIDR = '`^(?:((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))\.((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))\.((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))\.((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))(?:/((?:(?:0)|(?:3[0-2])|(?:[1-2]?[0-9]))))?)$`';

	/**
	 * @source https://www.regextester.com/93988
	 * @author anonymous
	 */
	const PATTERN_IPV6_CIDR = '`^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$`';

	/** @var string SERVER: REMOTE_ADDR entry */
	private string $_REMOTE_ADDR;

	/** @var string SERVER: HTTP_X_FORWARDED_FOR entry */
	private string $_HTTP_X_FORWARDED_FOR;

	/**
	 * Convert an IPv6 address to its numeric representation using GMP.
	 *
	 * @param string $ipv6 The IPv6 address.
	 * @return GMP The numeric representation of the IPv6 address.
	 */
	private function ipv6ToGmp(string $ipv6): GMP
	{
		// Convert IPv6 address to expanded format
		$expandedIp = inet_pton($ipv6);
		$binaryIp = bin2hex($expandedIp);

		// Convert binary format to GMP number
		return gmp_init($binaryIp, 16);
	}

	/**
	 * Convert a numeric representation of an IPv6 address back to its string representation.
	 *
	 * @param GMP $numericIp The numeric representation of the IPv6 address.
	 * @return string The string representation of the IPv6 address.
	 */
	private function gmpToIpv6(GMP $numericIp): string
	{
		$hex = gmp_strval($numericIp, 16);
		$hex = str_pad($hex, 32, '0', STR_PAD_LEFT);
		$binaryIp = pack('H*', $hex);
		return inet_ntop($binaryIp);
	}

	/**
	 * Find the highest bit where two IPv6 addresses differ.
	 *
	 * @param GMP $start The starting IPv6 address in numeric form.
	 * @param GMP $end The ending IPv6 address in numeric form.
	 * @return int The position of the highest differing bit.
	 */
	private function highestDifferingBit(GMP $start, GMP $end): int
	{
		$diff = gmp_xor($start, $end);
		$bitLength = 128;
		for ($i = 0; $i < $bitLength; $i++) {
			if (gmp_testbit($diff, $i)) {
				return $bitLength - $i - 1;
			}
		}
		return 0;
	}

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
	 * @param string $ip
	 * @return bool
	 */
	public function isIPv4(string $ip): bool
	{
		return !$this->isIPv6($ip);
	}

	/**
	 * @param string $ip
	 * @return bool
	 */
	public function isIPv6(string $ip): bool
	{
		return false !== strpos($ip, ':');
	}

	/**
	 * @param string $ip
	 * @return bool
	 */
	public function hasCIDR(string $ip): bool
	{
		return false !== strpos($ip, '/');
	}

	/**
	 * Validate IPV4 or CIDR
	 *
	 * @param string $ip
	 * @param bool $cidr [optional]
	 * @return bool
	 */
	public function check(string $ip, bool $cidr = false): bool
	{
		if($cidr && !strpos($ip, '/')) {
			return false;
		}
		$pattern = $this->isIPv6($ip) ? self::PATTERN_IPV6_CIDR : self::PATTERN_IPV4_CIDR;
		return $ip && preg_match($pattern, $ip);
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
	public function isBetweenIPv4(string $ipv4, string $startIP, string $endIP): bool
	{
		if($this->hasCIDR($ipv4)) {
			$range = $this->cidrToRange($ipv4);
			$ipStart = $range['ip_min_dec'] ?? false;
			$ipEnd = $range['ip_max_dec'] ?? false;
		}
		else {
			$ipStart = $ipEnd = ip2long($ipv4);
			if ($ipStart === false) {
				throw new InvalidArgumentException("Invalid IPv4 address format.");
			}
		}

		$rangeStart = ip2long($startIP);
		$rangeEnd = ip2long($endIP);
		if ($rangeStart === false) {
			throw new InvalidArgumentException("Invalid starting IPv4 address format.");
		}
		if ($rangeEnd === false) {
			throw new InvalidArgumentException("Invalid ending IPv4 address format.");
		}

		return ($ipStart >= $rangeStart && $ipEnd <= $rangeEnd);
	}

	/**
	 * Check if a given IPv6 address is within a specified IPv6 range.
	 *
	 * @param string $ip The IPv6 address to check.
	 * @param string $startIP The starting IPv6 address of the range.
	 * @param string $endIP The ending IPv6 address of the range.
	 * @return bool True if the IP is within the range, False otherwise.
	 */
	public function isBetweenIPv6(string $ip, string $startIP, string $endIP): bool
	{
		$ipNumeric = $this->ipv6ToGmp($ip);
		$startNumeric = $this->ipv6ToGmp($startIP);
		$endNumeric = $this->ipv6ToGmp($endIP);

		if(!$this->isIPv6($startIP) || !$this->check($startIP)) {
			throw new InvalidArgumentException("The IP address format is invalid.");
		}
		if(!$this->isIPv6($startIP) || !$this->check($startIP)) {
			throw new InvalidArgumentException("The starting IP address format is invalid.");
		}
		if(!$this->isIPv6($endIP) || !$this->check($endIP)) {
			throw new InvalidArgumentException("The ending IP address format is invalid.");
		}

		$start = $this->ipv6ToGmp($startIP);
		$end = $this->ipv6ToGmp($endIP);
		if (gmp_cmp($start, $end) > 0) {
			throw new InvalidArgumentException("The starting IP address must be less than or equal to the ending IP address.");
		}

		return gmp_cmp($ipNumeric, $startNumeric) >= 0 && gmp_cmp($ipNumeric, $endNumeric) <= 0;
	}

	/**
	 * Check if the given ipv4 is between given range
	 *
	 * @param string $ip
	 * @param string $startIP
	 * @param string $endIP
	 * @return bool
	 */
	public function isBetween(string $ip, string $startIP, string $endIP): bool
	{
		if($this->isIPv6($startIP) && $this->isIPv6($endIP)) {
			return $this->isBetweenIPv6($ip, $startIP, $endIP);
		}
		elseif($this->isIPv4($startIP) && $this->isIPv4($endIP)) {
			return $this->isBetweenIPv4($ip, $startIP, $endIP);
		}
		else {
			throw new InvalidArgumentException("The two IP addresses provided must be of the same type.");
		}
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

		if ($ip_dec === false) {
			throw new InvalidArgumentException("Invalid IPv4 address format.");
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
	 * Convert an IP range to a list of CIDR blocks.
	 *
	 * @param string $startIP The starting IPv6 address of the range.
	 * @param string $endIP The ending IPv6 address of the range.
	 * @return array The list of CIDR blocks representing the IP range.
	 */
	public function rangeToCIDRIPv6(string $startIP, string $endIP): array
	{
		if(!$this->isIPv6($startIP) || !$this->check($startIP)) {
			throw new InvalidArgumentException("The starting IP address format is invalid.");
		}
		if(!$this->isIPv6($endIP) || !$this->check($endIP)) {
			throw new InvalidArgumentException("The ending IP address format is invalid.");
		}

		$start = $this->ipv6ToGmp($startIP);
		$end = $this->ipv6ToGmp($endIP);
		if (gmp_cmp($start, $end) > 0) {
			throw new InvalidArgumentException("The starting IP address must be less than or equal to the ending IP address.");
		}

		$cidrs = [];
		while (gmp_cmp($start, $end) <= 0) {
			$maxDiffBit = $this->highestDifferingBit($start, $end);
			$maxCidrLength = 128 - $maxDiffBit;

			for ($mask = 128; $mask >= $maxCidrLength; $mask--) {
				$prefixMask = gmp_sub(gmp_pow(2, $mask), 1);
				$network = gmp_and($start, $prefixMask);

				if (gmp_cmp($network, $start) == 0) {
					$cidrs[] = $this->gmpToIpv6($start) . '/' . $mask;
					$start = gmp_add($network, gmp_pow(2, 128 - $mask));
					break;
				}
			}
		}
		return $cidrs;
	}

	/**
	 * Convert a range of IP addresses to CIDR notation.
	 *
	 * @param string $startIP The starting IP address of the range.
	 * @param string $endIP The ending IP address of the range.
	 * @return array An array of CIDR notations.
	 */
	public function rangeToCIDRIPv4(string $startIP, string $endIP): array
	{
		$start = ip2long($startIP);
		if ($start === false) {
			throw new InvalidArgumentException("The starting IP address format is invalid.");
		}

		$end = ip2long($endIP);
		if ($end === false) {
			throw new InvalidArgumentException("The ending IP address format is invalid.");
		}

		if ($start > $end) {
			throw new InvalidArgumentException("The starting IP address must be less than or equal to the ending IP address.");
		}

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
	 * Convert a range of IP addresses to CIDR notation.
	 *
	 * @param string $startIP The starting IP address of the range.
	 * @param string $endIP The ending IP address of the range.
	 * @return array An array of CIDR notations.
	 */
	public function rangeToCIDR(string $startIP, string $endIP): array
	{
		if($this->isIPv6($startIP) && $this->isIPv6($endIP)) {
			return $this->rangeToCIDRIPv6($startIP, $endIP);
		}
		elseif($this->isIPv4($startIP) && $this->isIPv4($endIP)) {
			return $this->rangeToCIDRIPv4($startIP, $endIP);
		}
		else {
			throw new InvalidArgumentException("The two IP addresses provided must be of the same type.");
		}
	}

	/**
	 * Calculate the number of IP addresses in a given CIDR block.
	 *
	 * @param string $cidr The CIDR block (e.g., "192.168.1.0/24").
	 * @return string The number of IP addresses in the CIDR block. STRING BECAUSE OF LENGTH
	 */
	public function countIPsInCIDR(string $cidr): string
	{
		if(!$mask = explode('/', $cidr)[1] ?? null) {
			return 1;
		}
		if($this->isIPv4($cidr)) {
			return 1 << (32 - (int) $mask);
		}
		if($this->isIPv6($cidr)) {
			// Total bits in an IPv6 address
			$totalBits = 128;

			// Calculate the number of IPs in the CIDR block
			$ipCount = gmp_pow(2, $totalBits - (int) $mask);
			return gmp_strval($ipCount);
		}
		return 0;
	}

	/**
	 * Calculate the number of IP v4 addresses in a given IP range.
	 *
	 * @param string $startIP The starting IP address of the range.
	 * @param string $endIP The ending IP address of the range.
	 * @return int The number of IP addresses in the range.
	 */
	public function countIPv4sInRange(string $startIP, string $endIP): int
	{
		$start = ip2long($startIP);
		if ($start === false) {
			throw new InvalidArgumentException("The starting IP address format is invalid.");
		}

		$end = ip2long($endIP);
		if ($end === false) {
			throw new InvalidArgumentException("The ending IP address format is invalid.");
		}

		if ($start > $end) {
			throw new InvalidArgumentException("The starting IP address must be less than or equal to the ending IP address.");
		}

		return ($end - $start + 1);
	}

	/**
	 * Calculate the number of IP addresses in a given IPv6 range.
	 *
	 * @param string $startIP The starting IPv6 address of the range.
	 * @param string $endIP The ending IPv6 address of the range.
	 * @return string The number of IP addresses in the range. STRING BECAUSE OF LENGTH
	 */
	public function countIPv6sInRange(string $startIP, string $endIP): string
	{
		if(!$this->isIPv6($startIP) || !$this->check($startIP)) {
			throw new InvalidArgumentException("The starting IP address format is invalid.");
		}
		if(!$this->isIPv6($endIP) || !$this->check($endIP)) {
			throw new InvalidArgumentException("The ending IP address format is invalid.");
		}

		$start = $this->ipv6ToGmp($startIP);
		$end = $this->ipv6ToGmp($endIP);
		if (gmp_cmp($start, $end) > 0) {
			throw new InvalidArgumentException("The starting IP address must be less than or equal to the ending IP address.");
		}

		// Calculate the difference and add 1
		$ipCount = gmp_add(gmp_sub($end, $start), 1);
		return gmp_strval($ipCount);
	}

	/**
	 * Calculate the number of IP v4 or v6 addresses in a given IP range.
	 *
	 * @param string $startIP The starting IP address of the range.
	 * @param string $endIP The ending IP address of the range.
	 * @return string The number of IP addresses in the range. STRING BECAUSE OF LENGTH FOR IPV6 ADDRESSES
	 */
	public function countIPsInRange(string $startIP, string $endIP): string
	{
		if($this->isIPv6($startIP) && $this->isIPv6($endIP)) {
			return $this->countIPv6sInRange($startIP, $endIP);
		}
		elseif($this->isIPv4($startIP) && $this->isIPv4($endIP)) {
			return $this->countIPv4sInRange($startIP, $endIP);
		}
		else {
			throw new InvalidArgumentException("The two IP addresses provided must be of the same type.");
		}
	}
}